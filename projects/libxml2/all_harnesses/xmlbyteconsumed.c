#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Include the project headers (absolute paths from the source tree) */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h" /* for xmlFreeDoc */

/* Fuzzer entry point required by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the library (no-op if already initialized) */
    xmlInitParser();

    /* xmlCreatePushParserCtxt expects an int size. Clamp to INT_MAX if needed. */
    int initsize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /*
     * Create a push parser context with the initial chunk set to the fuzzer input.
     * Use default SAX handler (NULL) and no user_data, no filename.
     */
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL,
                                                    (const char *)Data,
                                                    initsize,
                                                    NULL);
    if (ctxt != NULL) {
        /* Notify the parser of end of data to complete parsing */
        /* xmlParseChunk(ctxt, NULL, 0, 1) is the documented way to finish a push parse. */
        xmlParseChunk(ctxt, NULL, 0, 1);

        /* Call the target function under test */
        (void)xmlByteConsumed(ctxt);

        /* Free any document created during parsing: xmlFreeParserCtxt
           intentionally does not free ctxt->myDoc, so free it here if present. */
        if (ctxt->myDoc != NULL) {
            xmlFreeDoc(ctxt->myDoc);
            ctxt->myDoc = NULL;
        }

        /* Clean up the parser context */
        xmlFreeParserCtxt(ctxt);
    }

    /* Global cleanup (safe to call repeatedly) */
    xmlCleanupParser();

    return 0;
}
