#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Prefer absolute project headers as requested */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/xmlerror.h"

/* Fuzzing entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* Initialize the library (safe to call multiple times) */
    xmlInitParser();

    /* Optionally silence libxml2 error output to avoid noisy logs during fuzzing */
    /* The generic error callback takes a void* ctx and a const char* msg; passing
       NULL will disable the default behavior in many builds. */
    xmlSetGenericErrorFunc(NULL, NULL);

    /* xmlCreateMemoryParserCtxt takes an int size; clamp to INT_MAX to avoid overflow */
    int sz = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a parser context that will parse the provided memory buffer */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt((const char *)Data, sz);
    if (ctxt == NULL) {
        /* Nothing to do */
        xmlCleanupParser();
        return 0;
    }

    /*
     * Call the function under test.
     * The function may allocate an xmlDoc and store it in ctxt->myDoc.
     */
    (void)xmlParseExtParsedEnt(ctxt);

    /*
     * Ensure any document created during parsing is freed to avoid leaks.
     * In some code paths xmlFreeParserCtxt may not free ctxt->myDoc, so free it explicitly here.
     */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Free parser context and any remaining associated resources */
    xmlFreeParserCtxt(ctxt);

    /* Cleanup any global state created by libxml2 for this process */
    xmlCleanupParser();

    return 0;
}
