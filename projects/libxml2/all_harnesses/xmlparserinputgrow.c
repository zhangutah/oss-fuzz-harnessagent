#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>

/*
 * Fuzzer entry point.
 * Creates a memory parser context and a string input from the provided
 * Data, then calls xmlParserInputGrow() with a length derived from the
 * fuzzing input. Cleans up afterwards.
 *
 * Fixed: xmlNewStringInputStream expects a NUL-terminated string. The
 * original harness passed Data directly (not NUL-terminated), which made
 * strlen read past the buffer and caused heap-buffer-overflow. To fix
 * this we make a NUL-terminated copy (with a sensible cap) and pass that
 * to xmlNewStringInputStream.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* initialize parser library (no-op if already done) */
    xmlInitParser();

    /* Create a memory parser context based on the input bytes */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt((const char *)Data, (int)Size);
    if (ctxt == NULL) return 0;

    /* Make a NUL-terminated copy of the input for xmlNewStringInputStream.
     * Cap the amount copied to avoid excessive allocations from very large
     * fuzzer inputs. */
    const size_t MAX_COPY = 10 * 1024 * 1024; /* 10 MB cap */
    size_t copy_len = Size;
    if (copy_len > MAX_COPY) copy_len = MAX_COPY;

    char *tmp = (char *)malloc(copy_len + 1);
    if (tmp == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    memcpy(tmp, Data, copy_len);
    tmp[copy_len] = '\0';

    /* Create a parser input stream wrapping the NUL-terminated input bytes */
    xmlParserInputPtr in = xmlNewStringInputStream(ctxt, (const xmlChar *)tmp);

    free(tmp);

    if (in == NULL) {
        /* cleanup context if input creation failed */
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Derive an int 'len' from the first 4 bytes of the input (if available).
     * Clamp into a reasonable range to avoid trivial huge allocations while
     * still providing varied positive/negative values for fuzzing. */
    int len;
    if (Size >= 4) {
        uint32_t v = (uint32_t)Data[0] |
                     ((uint32_t)Data[1] << 8) |
                     ((uint32_t)Data[2] << 16) |
                     ((uint32_t)Data[3] << 24);
        /* Map v to range [-100000, 100000] */
        len = (int)(v % 200001u) - 100000;
    } else {
        len = (int)Size;
    }

    /* Call the function under test */
    (void)xmlParserInputGrow(in, len);

    /* Cleanup */
    xmlFreeInputStream(in);
    xmlFreeParserCtxt(ctxt);

    return 0;
}
