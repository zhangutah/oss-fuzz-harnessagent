// Fixed fuzz driver for xmlParseDocument to avoid leaking ctxt->myDoc
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Include libxml2 headers (use absolute paths in this workspace) */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"

/*
 * Fuzzer entry point for fuzzing xmlParseDocument(xmlParserCtxt *ctxt).
 *
 * This driver creates a memory parser context from the fuzzer input,
 * calls xmlParseDocument on it, frees the created document (if any),
 * and frees the context.
 *
 * Notes:
 *  - xmlInitParser() is called once (idempotent) to ensure library init.
 *  - If Size is larger than INT_MAX it is truncated to INT_MAX because
 *    libxml2 APIs expect int sizes.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        /* Initialize the parser library once */
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* xmlCreateMemoryParserCtxt takes an int size; guard against overflow */
    if (Size > (size_t)INT_MAX)
        Size = (size_t)INT_MAX;

    /* Create a memory parser context from the input buffer.
     * xmlCreateMemoryParserCtxt accepts a pointer to the buffer and its size.
     */
    xmlParserCtxt *ctxt = xmlCreateMemoryParserCtxt((const char *)Data, (int)Size);
    if (ctxt == NULL)
        return 0;

    /* Call the parser */
    (void)xmlParseDocument(ctxt);

    /* xmlParseDocument may create a document reachable via ctxt->myDoc.
     * xmlFreeParserCtxt() does not free ctxt->myDoc, so free it explicitly
     * to avoid leaks (see example usage in libxml2 sources).
     */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Free the parser context and associated resources */
    xmlFreeParserCtxt(ctxt);

    /* Do not call xmlCleanupParser() here; the fuzzer runtime may call it on exit. */
    return 0;
}
