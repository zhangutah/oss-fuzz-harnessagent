// Fuzz driver for:
//   int xmlAddXMLCatalog(xmlCatalogEntryPtr catal, const xmlChar * type,
//                        const xmlChar * orig, const xmlChar * replace);
// This harness includes the catalog implementation so the static function
// is available in the same translation unit. It builds a minimal
// xmlCatalogEntry structure, derives three strings from the fuzz input,
// and calls xmlAddXMLCatalog.
//
// Note: This driver is intended to be compiled together with the
// project sources (it includes the catalog implementation directly).
// Depending on your build system you may need to adjust include paths.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> /* for INT_MAX */

// libxml2 types and helpers are used by catalog.c; include xmlstring.h
// so xmlChar and xmlStrndup are declared. The implementation (.c) is
// included below so the static function xmlAddXMLCatalog is available.
#include "/src/libxml2/include/libxml/xmlstring.h"

// Include the implementation containing xmlAddXMLCatalog.
// This makes the static symbol visible to this translation unit.
// Note: including a .c file is intentional here for fuzzing the static
// function in-process.
#include "/src/libxml2/catalog.c"

// Fuzzer entry point expected by libFuzzer.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimal safety checks.
    if (Data == NULL || Size == 0) return 0;

    // Limit per-part size to avoid huge allocations that can OOM the fuzzer.
    // xmlNewCatalogEntry / xmlStrdup may allocate based on input lengths,
    // so cap to a small reasonable size.
    const size_t MAX_PART = 256; /* tuned to avoid large allocations */

    // Derive three lengths from the input but cap each to MAX_PART.
    size_t len1 = 0, len2 = 0, len3 = 0;
    size_t remaining = Size;

    if (remaining > 0) {
        len1 = remaining < MAX_PART ? remaining : MAX_PART;
        remaining = (remaining > len1) ? (remaining - len1) : 0;
    }
    if (remaining > 0) {
        len2 = remaining < MAX_PART ? remaining : MAX_PART;
        remaining = (remaining > len2) ? (remaining - len2) : 0;
    }
    if (remaining > 0) {
        len3 = remaining < MAX_PART ? remaining : MAX_PART;
        remaining = (remaining > len3) ? (remaining - len3) : 0;
    }

    /*
     * If the input was small we may not fill all parts; ensure we still try
     * to exercise code paths by making type at least zero-length string
     * (xmlStrndup with 0 is fine).
     */

    // Create xmlChar* strings using libxml2 helper (xmlStrndup).
    // Cast the input buffer to const xmlChar* per xmlStrndup's signature.
    const xmlChar *buf = (const xmlChar *)Data;
    xmlChar *type = NULL;
    xmlChar *orig = NULL;
    xmlChar *replace = NULL;

    // Guard lengths to fit into int for xmlStrndup's second parameter
    int ilen1 = (int)(len1 > (size_t)INT_MAX ? INT_MAX : (int)len1);
    int ilen2 = (int)(len2 > (size_t)INT_MAX ? INT_MAX : (int)len2);
    int ilen3 = (int)(len3 > (size_t)INT_MAX ? INT_MAX : (int)len3);

    if (ilen1 > 0)
        type = xmlStrndup(buf, ilen1);
    else
        type = xmlStrndup((const xmlChar *)"", 0);

    if (ilen2 > 0)
        orig = xmlStrndup(buf + len1, ilen2);
    else
        orig = NULL; // xmlAddXMLCatalog accepts orig == NULL

    if (ilen3 > 0)
        replace = xmlStrndup(buf + len1 + len2, ilen3);
    else
        replace = NULL;

    // Allocate a minimal catalog entry (top of an XML catalog).
    // Use malloc so it is independent; initialize fields used by xmlAddXMLCatalog.
    xmlCatalogEntryPtr catal = (xmlCatalogEntryPtr)malloc(sizeof(xmlCatalogEntry));
    if (catal == NULL) {
        if (type) xmlFree(type);
        if (orig) xmlFree(orig);
        if (replace) xmlFree(replace);
        return 0;
    }
    // Zero initialize then set required fields.
    memset(catal, 0, sizeof(xmlCatalogEntry));
    catal->next = NULL;
    catal->parent = NULL;

    // To avoid xmlAddXMLCatalog trying to fetch external catalog files,
    // ensure children is non-NULL so doregister will be 0.
    xmlCatalogEntryPtr child = (xmlCatalogEntryPtr)malloc(sizeof(xmlCatalogEntry));
    if (child == NULL) {
        free(catal);
        if (type) xmlFree(type);
        if (orig) xmlFree(orig);
        if (replace) xmlFree(replace);
        return 0;
    }
    memset(child, 0, sizeof(xmlCatalogEntry));
    child->next = NULL;
    child->parent = catal;
    child->children = NULL;
    child->type = XML_CATA_SYSTEM; // arbitrary valid entry type
    child->name = NULL;
    child->value = NULL;
    child->URL = NULL;
    child->prefer = XML_CATA_PREFER_NONE;
    child->dealloc = 0;
    child->depth = 0;
    child->group = NULL;

    catal->children = child;

    // catal must be of type XML_CATA_CATALOG or XML_CATA_BROKEN_CATALOG
    catal->type = XML_CATA_CATALOG;
    catal->name = NULL;
    catal->value = NULL;
    catal->URL = NULL;
    catal->prefer = XML_CATA_PREFER_NONE;
    catal->dealloc = 0;
    catal->depth = 0;
    catal->group = NULL;

    // Call the target function under test.
    // xmlAddXMLCatalog returns 0 on success, -1 on failure. We ignore the result.
    (void)xmlAddXMLCatalog(catal, (const xmlChar *)type, (const xmlChar *)orig, (const xmlChar *)replace);

    // Clean up allocated memory. Use xmlFree for xmlChar* and free for structs.
    if (type) xmlFree(type);
    if (orig) xmlFree(orig);
    if (replace) xmlFree(replace);

    // Important: xmlAddXMLCatalog may have appended new xmlCatalogEntry nodes
    // after 'child' (child->next -> ...). Those nodes were allocated by the
    // library (xmlNewCatalogEntry) and would leak across fuzzer iterations.
    // To avoid OOM across many iterations, free the appended entries here.
    {
        xmlCatalogEntryPtr cur = child->next;
        while (cur != NULL) {
            xmlCatalogEntryPtr next = cur->next;
            if (cur->name) xmlFree(cur->name);
            if (cur->value) xmlFree(cur->value);
            if (cur->URL) xmlFree(cur->URL);
            // Note: don't attempt to free cur->children (they are not used here
            // by xmlNewCatalogEntry in this scenario), but if some code does set
            // children, freeing them would require a full recursive free. In this
            // harness the entries appended are leaf-like and safe to free.
            free(cur);
            cur = next;
        }
        // Unlink the list to avoid dangling pointers (not strictly necessary
        // since we're about to free child and catal).
        child->next = NULL;
    }

    // Free the child we allocated. If xmlAddXMLCatalog updated child->value/URL
    // in-place, they must be freed too.
    if (child->name) xmlFree(child->name);
    if (child->value) xmlFree(child->value);
    if (child->URL) xmlFree(child->URL);
    free(child);
    free(catal);

    return 0;
}
