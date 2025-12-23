// Generate a fuzz driver based the given function signature in C language. Output the full driver code in reply.
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// // Example 1:
// 
// // xmlNodeSet *
// //xmlXPathDistinct (xmlNodeSet *nodes) {
// //    if (xmlXPathNodeSetIsEmpty(nodes))
// //	return(nodes);
// //
// //    xmlXPathNodeSetSort(nodes);
// //    return(xmlXPathDistinctSorted(nodes));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlNodeSet * xmlXPathDistinctSorted(xmlNodeSet * nodes);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Prefer the internal header found in the codebase for the target symbol. */
#include "/src/libxml2/include/libxml/xpathInternals.h"

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Fuzz driver for:
 *   xmlNodeSet * xmlXPathDistinctSorted(xmlNodeSet * nodes);
 *
 * This harness:
 *  - Parses the fuzzer input as XML using libxml2's xmlReadMemory().
 *  - Walks the resulting DOM and collects up to N node pointers into an
 *    xmlNodeSet structure.
 *  - Calls xmlXPathDistinctSorted() with that node set.
 *  - Cleans up the allocated structures and returns.
 *
 * Notes:
 *  - We avoid calling xmlCleanupParser() because it shuts down global
 *    parser state which can interfere with repeated fuzz iterations.
 *  - The harness keeps node count reasonable to avoid excessive allocations.
 */

/* Helper: ensure node set capacity and append a node. */
static void
nodeset_append(xmlNodeSetPtr set, xmlNodePtr node) {
    if (set == NULL)
        return;
    if (set->nodeMax <= 0) {
        /* start with a small capacity */
        set->nodeMax = 8;
        set->nodeTab = (xmlNodePtr *)malloc(set->nodeMax * sizeof(xmlNodePtr));
        if (set->nodeTab == NULL) {
            set->nodeMax = 0;
            return;
        }
    }
    if (set->nodeNr >= set->nodeMax) {
        int newMax = set->nodeMax * 2;
        xmlNodePtr *tmp = (xmlNodePtr *)realloc(set->nodeTab, newMax * sizeof(xmlNodePtr));
        if (tmp == NULL)
            return;
        set->nodeTab = tmp;
        set->nodeMax = newMax;
    }
    set->nodeTab[set->nodeNr++] = node;
}

/* Recursively traverse the tree and collect nodes (stop after limit). */
static void
collect_nodes(xmlNodePtr node, xmlNodeSetPtr set, int *collected, int limit) {
    for (xmlNodePtr cur = node; cur && *collected < limit; cur = cur->next) {
        /*
         * Collect element and text nodes as a representative subset.
         * Other node types can be collected too, but keeping it simple
         * reduces dependence on specific internals.
         */
        if (cur->type == XML_ELEMENT_NODE || cur->type == XML_TEXT_NODE) {
            nodeset_append(set, cur);
            (*collected)++;
            if (*collected >= limit) break;
        }
        if (cur->children)
            collect_nodes(cur->children, set, collected, limit);
    }
}

/* Fuzzer entry point expected by libFuzzer / OSS-Fuzz. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /*
     * Parse the fuzzer input as XML. Using XML_PARSE_RECOVER makes the
     * parser attempt to recover from malformed inputs instead of bailing out.
     */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz-input", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc == NULL) {
        /* Nothing parsed, nothing to do. */
        return 0;
    }

    /* Determine a reasonable maximum number of nodes to collect.
     * Use the first byte of Data (if available) to vary the limit across runs.
     */
    int limit = 16; /* default */
    if (Size >= 1) {
        /* keep limit bounded to avoid huge allocations */
        limit = 1 + (Data[0] % 128);
    }

    /* Allocate an empty xmlNodeSet structure. We'll manage nodeTab ourselves. */
    xmlNodeSetPtr set = (xmlNodeSetPtr)malloc(sizeof(xmlNodeSet));
    if (set == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }
    memset(set, 0, sizeof(*set));

    /* Collect nodes starting from the document root. */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    int collected = 0;
    if (root != NULL) {
        collect_nodes(root, set, &collected, limit);
    }

    /*
     * Call the target function under test.
     * The function is expected to modify / return the node set; we pass it
     * the allocated structure. It's part of the fuzz objective to see if
     * this call leads to crashes or memory errors.
     */
    if (set->nodeNr > 0) {
        /* xmlXPathDistinctSorted returns an xmlNodeSet * (maybe the same pointer). */
        xmlNodeSet *res = xmlXPathDistinctSorted(set);
        /* The returned pointer may be the same as 'set' or a different one.
         * To avoid leaking, if it's different we attempt to free it using
         * the public helper if available; otherwise free what we allocated.
         */
        if (res != set) {
            /* Try to free the returned set via xmlXPathFreeNodeSet if available. */
            /* xmlXPathFreeNodeSet is a libxml2 helper to free node sets. */
            xmlXPathFreeNodeSet(res);
            /* Free our original set if it wasn't freed by the function. */
            if (set != NULL) {
                if (set->nodeTab) free(set->nodeTab);
                free(set);
                set = NULL;
            }
        } else {
            /* The function returned the same pointer; free it via helper. */
            xmlXPathFreeNodeSet(set);
            set = NULL;
        }
    } else {
        /* No nodes collected; free our allocated set. */
        if (set->nodeTab) free(set->nodeTab);
        free(set);
        set = NULL;
    }

    /* Free the parsed document. Do not call xmlCleanupParser() here. */
    xmlFreeDoc(doc);

    return 0;
}
