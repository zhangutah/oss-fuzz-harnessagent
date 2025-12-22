#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <libxml/encoding.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

/* Fuzzer entry point must keep this signature */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        /* initialize libxml once in the process */
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /*
     * Use a small, conservative table of encodings to avoid handing off inputs
     * to handlers that may unintentionally allocate very large amounts of
     * memory for certain crafted inputs. Keeping this small also reduces the
     * chance of triggering pathological growth in conversion handlers.
     */
    const char *enc_names[] = {
        "UTF-8",
        "ISO-8859-1",
        "ASCII",
        "WINDOWS-1252"
    };
    size_t enc_count = sizeof(enc_names) / sizeof(enc_names[0]);

    /* Use the first byte to pick encoding; fallback to UTF-8 if not found */
    const char *pick = enc_names[Data[0] % enc_count];
    xmlCharEncodingHandler *handler = xmlFindCharEncodingHandler(pick);
    if (handler == NULL) {
        handler = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
        if (handler == NULL)
            return 0;
    }

    /* Create input and output buffers */
    xmlBufferPtr in = xmlBufferCreate();
    xmlBufferPtr out = xmlBufferCreate();
    if (in == NULL || out == NULL) {
        if (in) xmlBufferFree(in);
        if (out) xmlBufferFree(out);
        /* ensure we free handler if it was allocated by xmlCreate... */
        xmlCharEncCloseFunc(handler);
        return 0;
    }

    /* Use the remaining bytes as input to the conversion function.
       We use Data+1 so the first byte can select the handler. */
    const uint8_t *inp = Data + 1;
    size_t inpSize = (Size > 1) ? (Size - 1) : 0;

    /* Prevent unbounded allocations or pathological growth inside libxml
       conversion handlers by capping the input we feed into xmlBuffer.
       Keep this cap modest but sufficient to explore interesting behaviors. */
    const size_t MAX_INP_SIZE = 4096; /* 4 KB cap to avoid OOM in conversion */
    if (inpSize > MAX_INP_SIZE)
        inpSize = MAX_INP_SIZE;

    int inLen = (inpSize > (size_t)INT_MAX) ? INT_MAX : (int)inpSize;
    if (inLen > 0) {
        /* xmlBufferAdd accepts const xmlChar* and an int len */
        xmlBufferAdd(in, (const xmlChar *)inp, inLen);
    }

    /* Prefill the output buffer with a small slice of the input (if any)
       to vary output-buffer-related behavior. Keep it very small. */
    if (inLen > 0) {
        int prefill = inLen > 8 ? 8 : inLen;
        xmlBufferAdd(out, (const xmlChar *)inp, prefill);
    }

    /* Call the function under test. Ignore return value; we only want to
       exercise code paths inside the conversion handlers. */
    (void)xmlCharEncOutFunc(handler, out, in);

    /* Free the handler to avoid leaking allocations created by
       xmlFindCharEncodingHandler/xmlCreateCharEncodingHandler. */
    xmlCharEncCloseFunc(handler);

    /* Touch output buffer content to ensure result is used (avoid optimizing away)
       and to expose fuzzer to the produced output bytes. */
    const xmlChar *res = xmlBufferContent(out);
    size_t resLen = (res && out) ? (size_t)xmlBufferLength(out) : 0;
    if (res && resLen > 0) {
        /* Access a few bytes so sanitizer/coverage see them as used. */
        volatile unsigned char sink = 0;
        size_t n = resLen > 8 ? 8 : resLen;
        for (size_t i = 0; i < n; ++i) {
            sink ^= (unsigned char)res[i];
        }
        (void)sink;
    }

    xmlBufferFree(in);
    xmlBufferFree(out);

    return 0;
}