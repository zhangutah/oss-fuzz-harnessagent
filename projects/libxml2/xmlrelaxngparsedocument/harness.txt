// Fuzzer driver for xmlRelaxNGParseDocument (indirectly exercised via public APIs)
// This harness has been updated to ensure the target internal function
// xmlRelaxNGParseDocument is invoked directly.
//
// Note: xmlRelaxNGParseDocument is a static (file-scoped) function inside
// relaxng.c. To call it directly from this harness we include the
// implementation file relaxng.c into this translation unit. This is a
// common technique used in fuzzing harnesses when the target function is
// static. Depending on your build system, you may need to avoid also
// linking relaxng.c separately to prevent duplicate symbol errors.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#ifdef __cplusplus
}
#endif

/* Include the implementation to expose the static target function.
   Path is relative from fuzz/regexp.c to relaxng.c in the source tree. */
#include "../relaxng.c"

static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (!initialized) {
        /* Initialize the library and disable global error output to stderr to reduce noise. */
        xmlInitParser();
        /* Disable structured error callbacks (avoid printing errors to stderr). */
        xmlSetStructuredErrorFunc(NULL, NULL);
        /* Also disable the legacy generic error handler */
        xmlSetGenericErrorFunc(NULL, NULL);
        initialized = 1;
    }
}

/*
 * Fuzzer entry point
 *
 * We treat the input as an XML document containing a Relax-NG schema.
 * Steps:
 *  - Parse the input into an xmlDoc using xmlReadMemory().
 *  - Create an xmlRelaxNG parser context (xmlRelaxNGNewParserCtxt).
 *  - Call xmlRelaxNGParseDocument() directly with the parser context and the document root.
 *  - Free parser context, schema and document.
 *
 * Calling xmlRelaxNGParseDocument directly ensures the static target function is exercised.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    ensure_libxml_initialized();

    /* xmlReadMemory expects an int size */
    if (Size > INT_MAX) {
        return 0;
    }

    /* Parse the input bytes into an xmlDoc. Use recover to be tolerant to malformed input. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz-input", NULL,
                                 XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOENT);
    if (doc == NULL)
        return 0;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Create a RelaxNG parser context */
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewParserCtxt(NULL);
    if (pctxt == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Ensure some fields are initialized similarly to the normal parser path */
    pctxt->document = doc;

    /* Directly call the target static function from relaxng.c which
       is available in this TU because we included relaxng.c above. */
    xmlRelaxNGPtr schema = xmlRelaxNGParseDocument(pctxt, root);

    if (schema != NULL) {
        xmlRelaxNGFree(schema);
    }

    /* Free parser context and any associated resources */
    xmlRelaxNGFreeParserCtxt(pctxt);

    /* Free the parsed document */
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here: libFuzzer may call this harness repeatedly
       and xmlCleanupParser() may reset global state used across runs. */

    return 0;
}