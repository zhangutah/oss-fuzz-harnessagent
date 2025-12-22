// Fuzz driver for: int htmlParseDocument(htmlParserCtxt *ctxt);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Fixed issue: the original harness passed arbitrarily large inputs directly
// to the HTML parser which allowed the parser to allocate huge amounts of
// memory and crash the fuzzer with out-of-memory. To avoid this, we cap the
// input size to a reasonable maximum and copy the (possibly truncated) input
// into a local buffer which we keep live for the duration of parsing.
// Additionally, we set a maximum amplification factor on the parser context
// to avoid huge expansions (entities, repetition) causing very large
// allocations.
//
// To further avoid building a DOM (which can cause large allocations when
// concatenating text nodes), we replace the parser's SAX handler with an empty
// one so the parser runs in SAX-only mode and does not construct nodes.
//
// Keep the harness function signature exactly as required.

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "/src/libxml2/include/libxml/HTMLparser.h"
#include "/src/libxml2/include/libxml/parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Protect against huge inputs from the fuzzer that can trigger
       excessive allocations inside the parser. Choose a reasonable cap.
       Adjust MAX_INPUT_SIZE if you need more coverage but be mindful of
       memory constraints in the fuzzing environment. */
    const size_t MAX_INPUT_SIZE = 16 * 1024; /* 16 KB */

    if (Size > MAX_INPUT_SIZE)
        Size = MAX_INPUT_SIZE;

    /* Copy the (possibly truncated) input into a local buffer and NUL-terminate.
       Keep this buffer alive until after htmlFreeParserCtxt so the parser won't
       reference freed memory. */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Initialize libxml parser globals (safe to call repeatedly). */
    xmlInitParser();

    /* Create an HTML parser context from memory. */
    htmlParserCtxtPtr ctxt = htmlCreateMemoryParserCtxt(buf, (int)Size);
    if (ctxt == NULL) {
        free(buf);
        xmlCleanupParser();
        return 0;
    }

    /*
     * Limit amplification to avoid the parser expanding the input to an
     * enormous size (e.g., via entity expansion). This is intentionally low
     * to keep fuzzer memory usage reasonable.
     * The function takes an xmlParserCtxt*; htmlParserCtxtPtr is compatible,
     * but cast to the xmlParserCtxtPtr type to be explicit.
     */
    (void)xmlCtxtSetMaxAmplification((xmlParserCtxtPtr)ctxt, 50u);

    /*
     * Replace the SAX handlers with an empty handler to avoid building a DOM.
     * The default HTML SAX handlers create nodes which can cause large memory
     * allocations (particularly for long or repetitive text). By setting an
     * empty handler (all callbacks NULL) the parser will run in SAX-only mode
     * and won't construct the document tree.
     *
     * We copy into the existing ctxt->sax storage rather than changing the
     * pointer so htmlFreeParserCtxt can still free it correctly.
     */
    {
        htmlSAXHandler emptySax;
        memset(&emptySax, 0, sizeof(emptySax));
        if (ctxt->sax) {
            memcpy(ctxt->sax, &emptySax, sizeof(emptySax));
        }
        /* Prevent any user data-based allocations */
        ctxt->userData = NULL;
    }

    /* Parse the document (function under test). */
    (void)htmlParseDocument(ctxt);

    /* Free parser context and then our local buffer. */
    htmlFreeParserCtxt(ctxt);
    free(buf);

    /* Cleanup global parser state. */
    xmlCleanupParser();

    return 0;
}