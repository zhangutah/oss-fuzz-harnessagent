#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Include the relaxng.c implementation to be able to call the static
 * xmlRelaxNGParsePatterns function directly from this harness. This makes
 * the target function available in this translation unit.
 *
 * Note: The file path is relative to the fuzz directory: ../relaxng.c
 */
#include "../relaxng.c"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();

    /* Try parsing the fuzzer input directly as a RelaxNG schema in memory.
     * This exercises the xmlRelaxNGNewMemParserCtxt/xmlRelaxNGParse path
     * which will (internally) call xmlRelaxNGParsePatterns for suitable
     * inputs.
     */
    xmlRelaxNGParserCtxtPtr memctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
    if (memctxt) {
        xmlRelaxNGPtr schema = xmlRelaxNGParse(memctxt);
        if (schema)
            xmlRelaxNGFree(schema);
        xmlRelaxNGFreeParserCtxt(memctxt);
    }

    /* Parse the fuzzer input as an XML document in-memory.
     * Use XML_PARSE_NONET to avoid network fetches.
     * Suppress normal errors/warnings to avoid noisy output from libxml.
     */
    int parseOptions = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz-input.xml", NULL, parseOptions);

    if (doc == NULL) {
        /* If we couldn't parse as XML we've already tried the mem parser path above. */
        xmlCleanupParser();
        return 0;
    }

    /* Create a RelaxNG parser context from the parsed document.
     * The public xmlRelaxNGParse will walk the document and exercise the
     * internal parsing functions (including xmlRelaxNGParsePatterns).
     */
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewDocParserCtxt(doc);
    if (pctxt == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Call the public parse (keeps original behavior). */
    xmlRelaxNGPtr schema = xmlRelaxNGParse(pctxt);
    if (schema)
        xmlRelaxNGFree(schema);

    /* Additionally, directly call the target internal function to ensure it is exercised.
     * xmlRelaxNGParsePatterns is static in relaxng.c, but since we included relaxng.c above,
     * we can call it directly here.
     */
    if (doc->children != NULL) {
        /* group argument: try both 0 and 1 in separate calls to increase coverage */
        (void)xmlRelaxNGParsePatterns(pctxt, doc->children, 0);
        (void)xmlRelaxNGParsePatterns(pctxt, doc->children, 1);
    }

    xmlRelaxNGFreeParserCtxt(pctxt);
    xmlFreeDoc(doc);

    /* Global cleanup (safe to call repeatedly). */
    xmlCleanupParser();

    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
