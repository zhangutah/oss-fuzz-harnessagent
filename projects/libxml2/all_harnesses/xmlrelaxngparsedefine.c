#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

/* libxml2 headers */
#include <libxml/relaxng.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

/*
 * IMPORTANT:
 * To ensure the static/internal function xmlRelaxNGParseDefine from relaxng.c
 * is actually exercised by this harness we include the relaxng.c source file
 * directly. This makes the static function available in this translation unit
 * so we can call it directly with a parser context and a node constructed
 * from the fuzzer input.
 *
 * The relaxng.c file is in the parent directory of this fuzz harness:
 * ../relaxng.c  -> /src/libxml2/relaxng.c
 *
 * Note: Including a project source file into a harness like this is common
 * in fuzzing when the target is a static (file-local) function.
 */
#include "../relaxng.c"

/* Helper: recursively find the first <define> element node in a subtree */
static xmlNodePtr
find_define_node(xmlNodePtr node) {
    for (xmlNodePtr cur = node; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "define")) {
            return cur;
        }
        if (cur->children) {
            xmlNodePtr found = find_define_node(cur->children);
            if (found != NULL)
                return found;
        }
    }
    return NULL;
}

/*
 * Fuzz target for xmlRelaxNGParseDefine:
 * We feed the fuzzer input as the contents of an XML/Relax-NG fragment,
 * parse it into an xmlDoc, search for a <define> node and directly call
 * the (previously static) xmlRelaxNGParseDefine function with a proper
 * xmlRelaxNGParserCtxtPtr created from the memory buffer. This guarantees
 * the target function is invoked.
 *
 * The harness also keeps the calls minimal and frees resources to avoid leaks
 * across runs. We also mute libxml2 error callbacks to avoid noisy output.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the libxml2 library for this run */
    xmlInitParser();

#if LIBXML_VERSION >= 20607
    /* since libxml2 2.6.7 */
    xmlLoadExtDtdDefaultValue = 0;
#endif

    /* Mute generic error handling to avoid polluting output */
    xmlSetGenericErrorFunc(NULL, NULL);

    /* Copy input into a NUL-terminated buffer because some libxml2 APIs expect text */
    int bufSize = (Size > INT_MAX) ? INT_MAX : (int)Size;
    char *buf = (char *)malloc((size_t)bufSize + 1);
    if (buf == NULL) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(buf, Data, (size_t)bufSize);
    buf[bufSize] = '\0';

    /* Create a Relax-NG parser context from the fuzz input (memory buffer) */
    xmlRelaxNGParserCtxtPtr rngCtxt = xmlRelaxNGNewMemParserCtxt(buf, bufSize);

    /*
     * Parse the fuzz input into an xmlDoc so we can find a <define> node and
     * directly invoke xmlRelaxNGParseDefine on it. We use conservative parser
     * options to avoid network access and try to recover from malformed input.
     */
    xmlDocPtr doc = xmlReadMemory(buf, bufSize, "fuzz-input", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc != NULL && rngCtxt != NULL) {
        /* Mute parser-specific errors too */
        xmlRelaxNGSetParserErrors(rngCtxt, NULL, NULL, NULL);

        /* Try to find an explicit <define> element */
        xmlNodePtr root = xmlDocGetRootElement(doc);
        xmlNodePtr defineNode = NULL;
        if (root != NULL) {
            defineNode = find_define_node(root);
        }

        /*
         * If we found a <define> node, call the target function directly.
         * If no explicit <define> node is found, call it on the root element
         * (if any) to still exercise the function's handling of missing name
         * / invalid nodes.
         *
         * Note: xmlRelaxNGParseDefine was included from relaxng.c above,
         * so it's available in this translation unit.
         */
        if (defineNode != NULL) {
            /* Directly call the target function */
            (void)xmlRelaxNGParseDefine(rngCtxt, defineNode);
        } else if (root != NULL) {
            (void)xmlRelaxNGParseDefine(rngCtxt, root);
        }

        /*
         * Also call the public API xmlRelaxNGParse to keep prior behavior and
         * to exercise additional code paths; it will not hurt even if we've
         * already invoked the target function.
         */
        xmlRelaxNGPtr schema = xmlRelaxNGParse(rngCtxt);

        /* Free schema if parse succeeded */
        if (schema != NULL) {
            xmlRelaxNGFree(schema);
        }
    }

    /* Free parser context and xmlDoc (if any) */
    if (rngCtxt != NULL) {
        xmlRelaxNGFreeParserCtxt(rngCtxt);
    }
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    free(buf);

    /* Cleanup libxml2 state for this run */
    xmlCleanupParser();

    return 0;
}