#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* libxml2 public headers */
#include "/src/libxml2/include/libxml/xmlversion.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/relaxng.h"

/*
 * To access the (static) internal function xmlRelaxNGParseAttribute defined
 * inside relaxng.c, include the translation unit directly. This keeps the
 * function available to the harness even though it's static within the
 * original compilation unit.
 *
 * NOTE: The absolute path below is based on the project tree used by the
 * environment that produced the function location information.
 */
#include "/src/libxml2/relaxng.c"

/* Ensure libxml2 parser is initialized once. */
static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        /*
         * Previously the harness called xmlSetupParserForFork() here, but that
         * symbol may not be available in all builds and caused an undefined
         * reference at link time. Omit that call for portability/safety.
         */
        initialized = 1;
    }
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    ensure_libxml_initialized();

    /*
     * Create a RelaxNG parser context from the input buffer. This function
     * simply allocates and stores the buffer/size into the context in the
     * libxml2 code we included, which matches how the internal parsing
     * functions expect to find the data.
     */
    xmlRelaxNGParserCtxtPtr rngCtxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);

    /*
     * Try to parse the input as an XML document to obtain a node tree.
     * If parsing fails, fall back to creating a minimal node so we still
     * exercise xmlRelaxNGParseAttribute.
     *
     * Use XML_PARSE_NONET to avoid any network access while parsing.
     * Use XML_PARSE_RECOVER to get a doc even for malformed input where
     * possible.
     */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                 "fuzz-input.xml", NULL,
                                 XML_PARSE_NONET | XML_PARSE_RECOVER);

    xmlNodePtr node = NULL;
    if (doc != NULL) {
        node = xmlDocGetRootElement(doc);
    }

    /* If we don't have a usable node from parsing, fabricate a small one. */
    xmlDocPtr tmpDoc = NULL;
    if (node == NULL) {
        tmpDoc = xmlNewDoc(BAD_CAST "1.0");
        if (tmpDoc != NULL) {
            node = xmlNewDocNode(tmpDoc, NULL, BAD_CAST "fuzzRoot", NULL);
            if (node != NULL)
                xmlDocSetRootElement(tmpDoc, node);
        }
    }

    /* If we still don't have a node, nothing to do. */
    if (node != NULL) {
        /*
         * Call the target function. xmlRelaxNGParseAttribute is defined as
         * a static function inside relaxng.c; by including the .c file above
         * we are in the same translation unit and can call it directly.
         *
         * The function returns an xmlRelaxNGDefinePtr. We don't try to
         * inspect or free it here because it is an internal structure
         * (the purpose of fuzzing is to find crashes/UB).
         */
        (void) xmlRelaxNGParseAttribute(rngCtxt, node);
    }

    /* Cleanup created objects. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    if (tmpDoc != NULL) {
        /* xmlFreeDoc will free the fabricated node too */
        xmlFreeDoc(tmpDoc);
    }
    if (rngCtxt != NULL) {
        xmlRelaxNGFreeParserCtxt(rngCtxt);
    }

    /*
     * Note: We do not call xmlCleanupParser() here because the fuzzer will
     * invoke this function many times. Calling xmlCleanupParser() can be
     * done once at process exit if desired.
     */

    return 0;
}
