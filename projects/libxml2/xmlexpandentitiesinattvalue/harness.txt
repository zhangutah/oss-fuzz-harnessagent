#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Use public headers only (absolute paths to tree headers) */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/xmlmemory.h" /* for xmlFree, if needed */

/* Declare the internal function we want to fuzz (it's defined in parser.c).
   We declare it here to avoid including private/parser.h which depends on XML_HIDDEN. */
#ifdef __cplusplus
extern "C" {
#endif
extern xmlChar *xmlExpandEntitiesInAttValue(xmlParserCtxt *ctxt, const xmlChar *str, int normalize);
#ifdef __cplusplus
}
#endif

/* Some libxml2 setups require initialization */
static void ensure_libxml_initialized(void) {
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        inited = 1;
    }
}

/* Fuzzer entrypoint */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize library once */
    ensure_libxml_initialized();

    /* If no data, nothing to do */
    if (Data == NULL || Size == 0)
        return 0;

    /* Create a parser context for this invocation */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Ensure some fields used by the target are set to safe defaults */
    /* options influences the maxLength selection; leave as default (0) unless the fuzzer requests huge handling */
    ctxt->options = 0;
    /* Do NOT set inputNr to 1 without populating inputTab - that leads to xmlFreeParserCtxt
       freeing an uninitialized input and crashing. Leave it at 0 (default). */
    ctxt->inputNr = 0;

    /* Copy fuzzer input into a NUL-terminated xmlChar buffer */
    xmlChar *input = (xmlChar *)malloc(Size + 1);
    if (input == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    memcpy(input, Data, Size);
    input[Size] = 0; /* NUL terminate */

    /* Decide normalize flag from the first byte (simple deterministic mapping) */
    int normalize = (Data[0] & 1) ? 1 : 0;

    /* Call the target function */
    xmlChar *result = xmlExpandEntitiesInAttValue(ctxt, input, normalize);

    /* Free returned buffer if any */
    if (result != NULL)
        xmlFree(result);

    /* Clean up */
    free(input);
    xmlFreeParserCtxt(ctxt);

    /* Do not call xmlCleanupParser() here because the fuzzer process typically runs many inputs.
       If desired, it can be called at program exit. */

    return 0;
}
