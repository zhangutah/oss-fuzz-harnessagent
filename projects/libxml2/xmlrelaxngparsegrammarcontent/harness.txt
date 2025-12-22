// Fuzz driver for:
//   int xmlRelaxNGParseGrammarContent(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes);
//
// Strategy:
// - Parse the fuzzer input as an XML document with xmlReadMemory().
// - Create a xmlRelaxNGParserCtxt from the parsed doc (xmlRelaxNGNewDocParserCtxt).
// - Call the internal target function xmlRelaxNGParseGrammarContent to ensure it is exercised.
// - Clean up all libxml2 structures.
// - If parsing the document fails, fall back to creating a memory parser context and call the
//   target parse function to exercise the error path.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/* Silence relaxng parser errors during fuzzing */
static void
rng_error_cb(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

#ifdef LIBXML_RELAXNG_ENABLED

// Include the relaxng implementation directly so we can call the static
// xmlRelaxNGParseGrammarContent function from this translation unit.
//
// NOTE: Including a .c file is intentional here to expose the static target
// function to the fuzzer harness. The build setup for fuzzers typically
// compiles only the harness and the included source together.
#include "../relaxng.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Ensure libxml2 runtime is initialized */
    LIBXML_TEST_VERSION
    xmlInitParser();

    /* Parse the input bytes as an XML document. Use RECOVER and NONET to be safer. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz-input.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc != NULL) {
        xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewDocParserCtxt(doc);
        if (pctxt != NULL) {
            /* Suppress parser diagnostic output */
            xmlRelaxNGSetParserErrors(pctxt, rng_error_cb, rng_error_cb, NULL);

            /* Try to call the internal target function directly with the document root's children.
             * This ensures xmlRelaxNGParseGrammarContent() is exercised by the fuzzer.
             */
            xmlNodePtr root = xmlDocGetRootElement(doc);
            if (root != NULL) {
                // Pass the root's children (grammar content nodes) to the target.
                (void)xmlRelaxNGParseGrammarContent(pctxt, root->children);
            }

            /* Also call the public parse entry which may cover additional paths */
            xmlRelaxNGPtr schema = xmlRelaxNGParse(pctxt);
            if (schema != NULL) {
                xmlRelaxNGFree(schema);
            }

            xmlRelaxNGFreeParserCtxt(pctxt);
        }
        xmlFreeDoc(doc);
    } else {
        /* If XML parsing failed, create a memory parser ctxt and exercise the error path.
         * Also call the internal target with NULL nodes to exercise error handling.
         */
        xmlRelaxNGParserCtxtPtr pctxt2 = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
        if (pctxt2 != NULL) {
            xmlRelaxNGSetParserErrors(pctxt2, rng_error_cb, rng_error_cb, NULL);

            // Call internal target to exercise parse error paths.
            (void)xmlRelaxNGParseGrammarContent(pctxt2, NULL);

            xmlRelaxNGPtr schema2 = xmlRelaxNGParse(pctxt2);
            if (schema2 != NULL) {
                xmlRelaxNGFree(schema2);
            }
            xmlRelaxNGFreeParserCtxt(pctxt2);
        }
    }

    /* Cleanup libxml parser state (harmless to call repeatedly) */
    xmlCleanupParser();
    return 0;
}

#else

/* If libxml was built without RelaxNG support, provide a stub that does nothing. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    (void)Data;
    (void)Size;
    return 0;
}

#endif /* LIBXML_RELAXNG_ENABLED */