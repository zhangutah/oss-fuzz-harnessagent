// Fuzz driver for:
//   void xmlDumpXMLCatalogNode(xmlCatalogEntryPtr catal, xmlNodePtr catalog,
//                              xmlDocPtr doc, xmlNsPtr ns, xmlCatalogEntryPtr cgroup);
//
// Fuzzer entry point:
//   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
//
// This driver includes the catalog implementation directly so the static
// function xmlDumpXMLCatalogNode is available. It builds a small catalog
// entry list derived from the fuzz bytes and invokes xmlDumpXMLCatalogNode.
//
// Notes:
// - Must be compiled in the same build environment as the libxml2 sources.
// - Ensure LIBXML_CATALOG_ENABLED is defined so the catalog code is compiled.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define IN_LIBXML
#define LIBXML_CATALOG_ENABLED

// Include libxml2 public headers used by the driver (makes types available)
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

// Include the catalog implementation to get access to static symbols.
// Use the project-relative or absolute path depending on the build layout.
// Here we use the absolute path as discovered in the project.
#include "/src/libxml2/catalog.c"

// Helper: create a nul-terminated xmlChar* copied from input bytes.
static xmlChar *
dup_bytes_as_xmlchar(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0)
        return NULL;
    // limit string length to avoid huge allocations
    size_t n = len;
    if (n > 256) n = 256;
    xmlChar *s = (xmlChar *)malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, data, n);
    s[n] = '\0';
    return s;
}

static void
free_catalog_entries(xmlCatalogEntryPtr head) {
    xmlCatalogEntryPtr cur = head;
    while (cur != NULL) {
        xmlCatalogEntryPtr next = cur->next;
        if (cur->name) free(cur->name);
        if (cur->value) free(cur->value);
        if (cur->URL) free(cur->URL);
        free(cur);
        cur = next;
    }
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Initialize the parser state for libxml2 (safe to call multiple times).
    xmlInitParser();

    // Create a new minimal XML document and a catalog root node.
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) return 0;

    xmlNodePtr root = xmlNewDocNode(doc, NULL, BAD_CAST "catalog", NULL);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }
    xmlDocSetRootElement(doc, root);

    // Create a namespace attached to the root to pass to xmlDumpXMLCatalogNode.
    // Use a small constant namespace string; it's fine for fuzzing.
    xmlNsPtr ns = xmlNewNs(root, BAD_CAST "http://example.com/catalog", NULL);

    // Derive the number of catalog entries from the first byte.
    // Bound it reasonably to avoid heavy work.
    size_t offset = 0;
    size_t max_entries = 16;
    size_t count = (size_t)Data[0] % (max_entries + 1);
    offset = 1;

    // Prepare an initial previous pointer to build the list.
    xmlCatalogEntryPtr head = NULL;
    xmlCatalogEntryPtr prev = NULL;

    // A small list of candidate types to exercise various code paths.
    xmlCatalogEntryType types[] = {
        XML_CATA_NEXT_CATALOG,
        XML_CATA_GROUP,
        XML_CATA_PUBLIC,
        XML_CATA_SYSTEM,
        XML_CATA_REWRITE_SYSTEM,
        XML_CATA_DELEGATE_PUBLIC,
        XML_CATA_DELEGATE_SYSTEM,
        XML_CATA_URI,
        XML_CATA_REWRITE_URI,
        XML_CATA_DELEGATE_URI
    };
    const size_t ntypes = sizeof(types) / sizeof(types[0]);

    for (size_t i = 0; i < count && offset < Size; ++i) {
        // Allocate a catalog entry structure
        xmlCatalogEntryPtr ent = (xmlCatalogEntryPtr)calloc(1, sizeof(xmlCatalogEntry));
        if (ent == NULL) break;

        // Set a type derived from the input bytes
        ent->type = types[(Data[offset++] % ntypes)];

        // Use next bytes to build name/value strings. Each gets up to 16 bytes.
        size_t remain = (offset < Size) ? (Size - offset) : 0;
        size_t use_for_name = (remain > 0) ? (size_t)(Data[offset] % 17) : 0; // 0..16
        if (use_for_name > remain) use_for_name = remain;
        xmlChar *name = NULL;
        if (use_for_name > 0) {
            name = dup_bytes_as_xmlchar(Data + offset, use_for_name);
            offset += use_for_name;
        }

        remain = (offset < Size) ? (Size - offset) : 0;
        size_t use_for_value = (remain > 0) ? (size_t)(Data[offset] % 17) : 0; // 0..16
        if (use_for_value > remain) use_for_value = remain;
        xmlChar *value = NULL;
        if (use_for_value > 0) {
            value = dup_bytes_as_xmlchar(Data + offset, use_for_value);
            offset += use_for_value;
        }

        // Populate fields
        ent->name = name;
        ent->value = value;
        ent->URL = NULL;
        ent->prefer = XML_CATA_PREFER_NONE;
        ent->dealloc = 0;
        ent->depth = 0;
        ent->group = NULL;

        // Link into list
        if (prev == NULL) {
            head = ent;
        } else {
            prev->next = ent;
        }
        prev = ent;
    }

    // Choose a cgroup parameter: either NULL or head->next depending on a byte.
    xmlCatalogEntryPtr cgroup = NULL;
    if (head != NULL && Size > 1 && (Data[Size - 1] & 1) && head->next != NULL) {
        cgroup = head->next;
    }

    // Call the target function under test.
    // It will create nodes under 'root' and use 'doc' and 'ns'.
    // Wrapping the call in a simple error handling guard.
    xmlDumpXMLCatalogNode(head, root, doc, ns, cgroup);

    // Cleanup: free our created catalog entries and XML document and namespace.
    free_catalog_entries(head);

    // Do NOT free 'ns' explicitly here 	6 xmlFreeDoc will free the namespace(s)
    // attached to the document, avoiding double-free / use-after-free.
    if (doc != NULL)
        xmlFreeDoc(doc);

    // Cleanup the parser (no-op if other fuzz calls will reuse).
    // Do not call xmlCleanupParser unconditionally in multi-threaded environments,
    // but for a simple fuzzer single-threaded run, it's acceptable.
    // xmlCleanupParser();

    return 0;
}
