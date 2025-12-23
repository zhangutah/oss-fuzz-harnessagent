#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the libxml2 public header for parser ctx type and helpers */
#include <libxml/xmlschemas.h>

/*
 * Include the implementation unit directly so we can call the static
 * function xmlSchemaCheckSRCRedefineFirst from this translation unit.
 *
 * Adjust the path below if your build layout differs.
 */
#include "/src/libxml2/xmlschemas.c"

/*
 * Fuzzer entry point expected by libFuzzer / LLVMFuzzer.
 *
 * This takes the fuzzer-provided data, hands it to the libxml2
 * schema memory parser to create a parser context, then calls the
 * target function xmlSchemaCheckSRCRedefineFirst with that context.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Make a null-terminated copy of the input for xmlSchemaNewMemParserCtxt. */
    char *buf = (char *)malloc(Size + 1);
    if (!buf)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Create a parser context from the in-memory buffer. */
    xmlSchemaParserCtxtPtr pctxt = xmlSchemaNewMemParserCtxt(buf, (int)Size);
    if (pctxt == NULL) {
        free(buf);
        return 0;
    }

    /* Disable parser callbacks (optional) to avoid noisy output. */
    xmlSchemaSetParserErrors(pctxt, NULL, NULL, NULL);

    /*
     * Parse the provided data into schema structures so the fuzzer input
     * actually influences the internal state. This exercises parsing logic
     * and populates the parser context (constructor, redefs, etc.).
     */
    xmlSchemaPtr schema = xmlSchemaParse(pctxt);

    /*
     * Ensure the construction context exists on the parser context.
     * xmlSchemaCheckSRCRedefineFirst dereferences the constructor via
     * WXS_CONSTRUCTOR(pctxt)->redefs; create and attach one if missing.
     *
     * xmlSchemaConstructionCtxtCreate is defined in the included xmlschemas.c
     * and accepts the dictionary pointer (pctxt->dict).
     */
    if (pctxt->constructor == NULL) {
        /* xmlSchemaConstructionCtxtCreate returns xmlSchemaConstructionCtxtPtr */
        pctxt->constructor = xmlSchemaConstructionCtxtCreate(pctxt->dict);
        if (pctxt->constructor != NULL)
            pctxt->ownsConstructor = 1;
    }

    /*
     * Call the target function.
     * Note: xmlSchemaCheckSRCRedefineFirst is defined static in the
     * included .c file so it is callable from this TU.
     */
    (void)xmlSchemaCheckSRCRedefineFirst(pctxt);

    /* Clean up. */
    if (schema != NULL)
        xmlSchemaFree(schema);
    xmlSchemaFreeParserCtxt(pctxt);
    free(buf);

    return 0;
}