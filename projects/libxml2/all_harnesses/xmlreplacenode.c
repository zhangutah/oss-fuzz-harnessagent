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
// // xmlNode *
// //xmlDocSetRootElement(xmlDoc *doc, xmlNode *root) {
// //    xmlNodePtr old = NULL;
// //
// //    if (doc == NULL) return(NULL);
// //    if ((root == NULL) || (root->type == XML_NAMESPACE_DECL))
// //	return(NULL);
// //    old = doc->children;
// //    while (old != NULL) {
// //	if (old->type == XML_ELEMENT_NODE)
// //	    break;
// //        old = old->next;
// //    }
// //    if (old == root)
// //        return(old);
// //    xmlUnlinkNodeInternal(root);
// //    if (xmlSetTreeDoc(root, doc) < 0)
// //        return(NULL);
// //    root->parent = (xmlNodePtr) doc;
// //    if (old == NULL) {
// //	if (doc->children == NULL) {
// //	    doc->children = root;
// //	    doc->last = root;
// //	} else {
// //	    xmlAddSibling(doc->children, root);
// //	}
// //    } else {
// //	xmlReplaceNode(old, root);
// //    }
// //    return(old);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlNode * xmlReplaceNode(xmlNode * old, xmlNode * cur);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlNode * xmlReplaceNode(xmlNode * old, xmlNode * cur);
// Fuzzer entry: LLVMFuzzerTestOneInput
//
// Builds two small XML documents from the input bytes (split in half) and calls
// xmlReplaceNode on the root element of the first document, using the root of
// the second document as the replacement node (if available).
//
// Uses libxml2 APIs (xmlReadMemory, xmlDocGetRootElement, xmlReplaceNode,
// xmlFreeNode, xmlFreeDoc). Initializes libxml parser on first use.
//
// Note: compile and link with libxml2 (e.g., `-lxml2`) when building the fuzzer.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        /* avoid global state -> disable some catalog/network features */
        xmlSubstituteEntitiesDefault(1);
        inited = 1;
    }

    /* Split input into two parts to build two XML documents */
    size_t half = Size / 2;
    size_t len1 = half;
    size_t len2 = Size - half;

    const char *prefix = "<root>";
    const char *suffix = "</root>";
    size_t pfx_len = strlen(prefix);
    size_t sfx_len = strlen(suffix);

    /* Build wrapped buffer 1: <root> ...data1... </root> */
    size_t wrap1_len = pfx_len + len1 + sfx_len;
    if (wrap1_len == 0) return 0;
    if (wrap1_len >= (size_t)INT_MAX) { /* guard for xmlReadMemory int parameter */
        /* Too large to handle sensibly; skip this input. */
        return 0;
    }
    char *wrap1 = (char *)malloc(wrap1_len);
    if (!wrap1) return 0;
    memcpy(wrap1, prefix, pfx_len);
    if (len1 > 0) memcpy(wrap1 + pfx_len, Data, len1);
    memcpy(wrap1 + pfx_len + len1, suffix, sfx_len);

    /* Build wrapped buffer 2: <root> ...data2... </root> */
    size_t wrap2_len = pfx_len + len2 + sfx_len;
    if (wrap2_len >= (size_t)INT_MAX) {
        free(wrap1);
        return 0;
    }
    char *wrap2 = (char *)malloc(wrap2_len);
    if (!wrap2) { free(wrap1); return 0; }
    memcpy(wrap2, prefix, pfx_len);
    if (len2 > 0) memcpy(wrap2 + pfx_len, Data + len1, len2);
    memcpy(wrap2 + pfx_len + len2, suffix, sfx_len);

    /* Parse both buffers. Use conservative parser options to reduce side-effects. */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc1 = xmlReadMemory(wrap1, (int)wrap1_len, "fuzz1.xml", NULL, parseOptions);
    xmlDocPtr doc2 = xmlReadMemory(wrap2, (int)wrap2_len, "fuzz2.xml", NULL, parseOptions);

    free(wrap1);
    free(wrap2);

    if (doc1 == NULL) {
        if (doc2) xmlFreeDoc(doc2);
        return 0;
    }

    /* Select nodes: use the document root elements as candidates.
       xmlReplaceNode requires old->parent != NULL, root's parent is the doc, so it's valid. */
    xmlNodePtr old = xmlDocGetRootElement(doc1);
    if (old == NULL) {
        xmlFreeDoc(doc1);
        if (doc2) xmlFreeDoc(doc2);
        return 0;
    }

    xmlNodePtr cur = NULL;
    if (doc2 != NULL) {
        cur = xmlDocGetRootElement(doc2);
        /* cur may be NULL if doc2 parsed but has no root element */
    }

    /* Call the target function under test */
    xmlNodePtr replaced = xmlReplaceNode(old, cur);

    /* xmlReplaceNode returns the old node (unlinked) on success, or NULL on failure.
       If non-NULL, free the returned node to avoid leaks. */
    if (replaced != NULL) {
        /* xmlFreeNode is appropriate for a single node that has been unlinked */
        xmlFreeNode(replaced);
    }

    /* Free documents. If cur was moved into doc1, it was unlinked from doc2 and freeing
       doc2 is still appropriate. Freeing doc1 will free nodes now present in it. */
    xmlFreeDoc(doc1);
    if (doc2) xmlFreeDoc(doc2);

    /* Note: do not call xmlCleanupParser() here; libFuzzer may call the fuzzer function many times.
       xmlCleanupParser() could be called at program shutdown if desired. */

    return 0;
}