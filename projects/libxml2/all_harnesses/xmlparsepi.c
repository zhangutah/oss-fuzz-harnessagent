#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include libxml2 headers (use absolute paths from the workspace) */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Fuzz target for:
 *     void xmlParsePI(xmlParserCtxt * ctxt);
 *
 * Strategy:
 *  - Build a null-terminated copy of the fuzzer input.
 *  - Create a parser context using xmlCreateDocParserCtxt which prepares
 *    an input stream from the given string.
 *  - Disable SAX callbacks on the context to avoid SAX handlers being
 *    invoked when the parser context is in an incomplete state.
 *  - Call xmlParsePI(ctxt) to exercise the processing-instruction parsing.
 *  - Clean up the parser context.
 *
 * Notes:
 *  - xmlCreateDocParserCtxt expects a C string (xmlChar*), so we append a
 *    terminating NUL to the input. Inputs containing internal NULs will be
 *    effectively truncated at the first NUL, but that's acceptable for this
 *    fuzz harness.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Limit the size to a reasonable amount to avoid excessively large allocations. */
    const size_t max_alloc = 16 * 1024 * 1024; /* 16MB */
    size_t use_size = Size;
    if (use_size > max_alloc) use_size = max_alloc;

    /* Make a NUL-terminated copy of the input as xmlCreateDocParserCtxt expects a string. */
    char *buf = (char *)malloc(use_size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, use_size);
    buf[use_size] = '\0';

    /* Create a parser context from the provided buffer */
    xmlParserCtxtPtr ctxt = xmlCreateDocParserCtxt((const xmlChar *)buf);
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /*
     * Prevent SAX callbacks from running: xmlParsePI may invoke the
     * processingInstruction SAX callback which expects other parser state
     * to be present (document, current node, etc.). When fuzzing a single
     * function this state may be missing and lead to crashes. Disabling SAX
     * here avoids that.
     */
    ctxt->disableSAX = 1;
    /* NOTE: Do NOT set ctxt->sax = NULL here — internal error handling
     * (xmlCtxtVErr and friends) may dereference ctxt->sax. Rely on
     * disableSAX to prevent SAX callbacks. */

    /*
     * The xmlParsePI function expects the parser current position to be at a
     * processing-instruction start ("<?"). Calling xmlParsePI with arbitrary
     * input will exercise the function's checks and branches (including early
     * returns). We call it directly to fuzz its behavior.
     */
    xmlParsePI(ctxt);

    /* Clean up */
    xmlFreeParserCtxt(ctxt);
    free(buf);

    return 0;
}
