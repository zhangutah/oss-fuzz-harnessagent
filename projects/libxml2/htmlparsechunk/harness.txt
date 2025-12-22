#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

/* Prefer absolute project headers as discovered */
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point expected by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Nothing to do for empty input */
    if (Data == NULL || Size == 0)
        return 0;

    /* Ensure libxml is initialized/compatible */
    LIBXML_TEST_VERSION;
    xmlInitParser();

#ifdef LIBXML_PUSH_ENABLED
    /*
     * Use a SAX handler (even if it's all-NULL) so that the parser runs in
     * SAX-only mode and does not build a DOM. Building the DOM can consume
     * large amounts of memory for attacker-controlled inputs (large text
     * nodes, etc.). Passing a non-NULL sax pointer causes the parser to use
     * callbacks instead of creating nodes.
     */
    htmlSAXHandler sax;
    memset(&sax, 0, sizeof(sax));
    htmlParserCtxtPtr ctxt = htmlCreatePushParserCtxt(&sax, NULL, NULL, 0, NULL, XML_CHAR_ENCODING_NONE);
#else
    /* If push mode is not enabled at compile time, we cannot fuzz htmlParseChunk.
       Return early after cleanup. */
    xmlCleanupParser();
    return 0;
#endif

    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Prevent the fuzzer from feeding arbitrarily large inputs that can cause
       huge allocations inside libxml2 and exceed ASAN / fuzzer memory limits.
       Cap the total bytes processed. */
    const size_t MAX_TOTAL_BYTES = 64 * 1024; /* 64 KB - reduced to be conservative */
    size_t to_process = Size;
    if (to_process > MAX_TOTAL_BYTES) {
        to_process = MAX_TOTAL_BYTES;
    }

    /* Feed the (possibly truncated) input to htmlParseChunk in reasonably sized pieces
       to exercise streaming behavior. htmlParseChunk takes an int for size, so bound chunk sizes. */
    const unsigned char *ptr = Data;
    size_t remaining = to_process;
    const int CHUNK_MAX = 1024; /* smaller streaming chunks to reduce internal buffering */

    while (remaining > 0) {
        int this_len = (int)((remaining > (size_t)CHUNK_MAX) ? CHUNK_MAX : remaining);
        /* htmlParseChunk expects a const char* */
        (void)htmlParseChunk(ctxt, (const char *)ptr, this_len, 0);

        ptr += this_len;
        remaining -= this_len;
    }

    /* Signal termination to the parser so it can finish and check EOF handling */
    htmlParseChunk(ctxt, NULL, 0, 1);

    /* Free context and cleanup parser global state */
    htmlFreeParserCtxt(ctxt);
    xmlCleanupParser();

    return 0;
}