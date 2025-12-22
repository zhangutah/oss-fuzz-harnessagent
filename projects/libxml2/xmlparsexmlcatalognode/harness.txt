/*
 Fuzz driver for xmlParseXMLCatalogNode

 This fuzz driver parses the fuzzer input as an XML document and walks the
 top-level nodes, calling xmlParseXMLCatalogNode on each. To avoid leaking
 memory allocated by the catalog code (xmlNewCatalogEntry and friends),
 xmlCatalogCleanup() is invoked after processing the document to free
 catalog-related global state.

 Note: xmlParseXMLCatalogNode is an internal/static function in catalog.c.
 Including the source file here exposes it in this translation unit so it
 can be invoked by the fuzzer entry point.
*/

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/catalog.h>

/* Expose catalog internals (including xmlParseXMLCatalogNode) in this TU. */
#ifndef LIBXML_CATALOG_ENABLED
#define LIBXML_CATALOG_ENABLED
#endif

/* Include the catalog implementation to get access to the static function. */
#include "/src/libxml2/catalog.c"

/*
 * Fuzzer entry point.
 *
 * Parse the input bytes as an XML document (NONET and RECOVER) and call
 * xmlParseXMLCatalogNode() on each top-level node. After finishing, call
 * xmlCatalogCleanup() to free any catalog entries and avoid leaks, then
 * cleanup the parser.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the libxml2 parser */
    xmlInitParser();

    /*
     * Parse the input buffer as an XML document.
     * Use NONET to avoid network access during fuzzing, and RECOVER to be
     * permissive with malformed inputs.
     */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml",
                                  NULL, XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /*
     * Iterate over the top-level nodes (siblings of the root element and
     * other children of the document) and invoke the target function.
     *
     * Pass NULL for parent and cgroup. Use XML_CATA_PREFER_NONE as the
     * prefer value to cover the default branch in the target code.
     */
    xmlNodePtr cur = doc->children;
    while (cur != NULL) {
        /* Call the internal function from catalog.c (included above). */
        xmlParseXMLCatalogNode(cur, XML_CATA_PREFER_NONE, NULL, NULL);
        cur = cur->next;
    }

    /* Free the document */
    xmlFreeDoc(doc);

    /*
     * Cleanup catalog global state to free entries allocated by
     * xmlParseXMLCatalogNode / xmlNewCatalogEntry.
     *
     * This prevents the memory leak reported by LeakSanitizer where catalog
     * entries remain allocated between fuzzing inputs.
     */
    xmlCatalogCleanup();

    /* Cleanup the parser state */
    xmlCleanupParser();

    return 0;
}
