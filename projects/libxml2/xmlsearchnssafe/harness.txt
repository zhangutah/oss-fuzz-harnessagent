#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Public libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>

/* Declare the private function we are fuzzing.
 * The real declaration lives in a private header; we declare it here
 * so we can call it without including the private header that expects
 * other internal macros (like XML_HIDDEN).
 */
#ifdef __cplusplus
extern "C" {
#endif
int xmlSearchNsSafe(xmlNode *node, const xmlChar *href, xmlNs **out);
#ifdef __cplusplus
}
#endif

/*
 * Fuzzer entry point for libFuzzer.
 *
 * This driver treats the fuzzer input as XML document bytes and also
 * uses the same bytes as the namespace prefix to search for.
 *
 * It:
 *  - attempts to parse the input as an XML document via xmlReadMemory
 *  - if parsing fails, creates a minimal document with a single element
 *  - builds a prefix string from the input (bounded to INT_MAX)
 *  - calls xmlSearchNsSafe on the document element
 *  - cleans up allocated libxml2 structures
 *
 * Notes:
 *  - xmlSearchNsSafe expects a prefix (const xmlChar*) even though some
 *    declarations may refer to it as href; we follow the function definition.
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml */
    xmlInitParser();

    /* Parse input bytes as XML document */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz_input.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOWARNING | XML_PARSE_NOERROR);

    xmlNodePtr node = NULL;

    if (doc != NULL) {
        /* Get the root element (may be NULL if doc is empty) */
        node = xmlDocGetRootElement(doc);
    }

    /* If parsing failed or no root, create a minimal document and root element */
    if (doc == NULL || node == NULL) {
        if (doc == NULL) {
            doc = xmlNewDoc(BAD_CAST "1.0");
            if (doc == NULL) {
                xmlCleanupParser();
                return 0;
            }
        }
        /* Create a single element root and set it as the document root */
        xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "fuzzRoot");
        if (root == NULL) {
            xmlFreeDoc(doc);
            xmlCleanupParser();
            return 0;
        }
        xmlDocSetRootElement(doc, root);
        node = root;
    }

    /* Prepare prefix: use fuzzer bytes (bounded to INT_MAX for xmlStrndup) */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    xmlChar *prefix = xmlStrndup((const xmlChar *)Data, len);
    if (prefix == NULL) {
        /* cleanup */
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Call the target function */
    xmlNsPtr found = NULL;
    /* xmlSearchNsSafe returns 0 on success, -1 on alloc failure, 1 on other errors */
    (void)xmlSearchNsSafe(node, prefix, &found);

    /* No need to inspect 'found' for this fuzzer - just exercise the API.
       If found points to memory managed by libxml2, it is part of the doc and will
       be freed by xmlFreeDoc below. Do not free 'found' directly. */

    /* Cleanup */
    xmlFree(prefix);
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return 0;
}
