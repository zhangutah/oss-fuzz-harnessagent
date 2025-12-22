#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* public libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>

/* Ensure XML_HIDDEN is defined so private headers parse correctly */
#ifndef XML_HIDDEN
#define XML_HIDDEN
#endif

/* internal header exposing xmlStaticCopyNodeList */
#include "/src/libxml2/include/private/tree.h"

/*
 * Fuzzer entry point
 *
 * This harness:
 *  - parses the input bytes as an XML document (xmlReadMemory)
 *  - creates a fresh target document
 *  - calls the internal function xmlStaticCopyNodeList to copy the node list
 *    from the parsed document into the new document
 *  - frees the copied nodes and both documents
 *
 * Note: xmlStaticCopyNodeList is an internal API; we include the private
 * header to get its declaration.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    xmlDocPtr doc = NULL;
    xmlDocPtr newdoc = NULL;
    xmlNodePtr copied = NULL;

    if (Data == NULL || Size == 0) return 0;

    /* Initialize libxml2 parser environment (safe to call multiple times) */
    xmlInitParser();

    /*
     * Parse the input as an XML document. Use recover mode to be forgiving
     * with malformed inputs and avoid producing excessive errors.
     */
    doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz_input.xml",
                       NULL,
                       XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        /* Nothing to do if parsing failed */
        xmlCleanupParser();
        return 0;
    }

    /* Create a new empty document as the target for the copy */
    newdoc = xmlNewDoc(BAD_CAST "1.0");
    if (newdoc == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /*
     * Call the internal function under test.
     * Provide the head of the node list from the parsed document.
     * Use NULL for parent to exercise the code paths where the copied nodes
     * are not attached to a parent node.
     */
    copied = xmlStaticCopyNodeList(doc->children, newdoc, NULL);

    /*
     * If we received a copy, free the node list. xmlFreeNodeList will free
     * the nodes and their children correctly.
     */
    if (copied != NULL) {
        xmlFreeNodeList(copied);
    }

    /* Free documents */
    xmlFreeDoc(newdoc);
    xmlFreeDoc(doc);

    /* Cleanup libxml2 parser */
    xmlCleanupParser();

    return 0;
}
