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
// // xmlNs **
// //xmlGetNsList(const xmlDoc *doc, const xmlNode *node)
// //{
// //    xmlNsPtr *ret;
// //
// //    xmlGetNsListSafe(doc, node, &ret);
// //    return(ret);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlGetNsListSafe(const xmlDoc * doc, const xmlNode * node, xmlNs *** out);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for xmlGetNsListSafe
// Build note: link with libxml2 (e.g. -lxml2) and include libxml2 headers.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

/* Libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Fuzzer entry point
 *
 * This driver:
 *  - Parses the incoming byte blob as an XML document using xmlReadMemory.
 *  - Calls xmlGetNsListSafe on the document's root element (if any).
 *  - Frees returned namespace list (array) and the parsed document.
 *
 * Notes:
 *  - We avoid xmlCleanupParser() inside LLVMFuzzerTestOneInput because it
 *    is global and not safe to call between fuzzing inputs.
 *  - xmlInitParser() is called once on the first invocation to ensure libxml
 *    is initialized.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /*
         * Initialize libxml2 once. Do not call xmlCleanupParser()
         * here (or per-input) because that can interfere with subsequent calls.
         */
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* xmlReadMemory expects an int length; clamp to INT_MAX to be safe. */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Parse options: disable network access and suppress errors/warnings */
    int parseOptions = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_RECOVER;

    /* xmlReadMemory treats buffer as a char*; it's okay if data isn't NUL-terminated. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, len, NULL, NULL, parseOptions);
    if (doc == NULL) {
        /* Couldn't parse XML; nothing to do. */
        return 0;
    }

    /* Get the document element (root). If absent, free and return. */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Call xmlGetNsListSafe to obtain the in-scope namespaces for the node. */
    xmlNs **nslist = NULL;
    /* Note: xmlGetNsListSafe returns 0 on success, 1 if no namespaces were found,
       -1 if memory allocation failed. Regardless, if nslist != NULL it must be freed. */
    (void)xmlGetNsListSafe(doc, root, &nslist);

    if (nslist != NULL) {
        /* The function returns an array allocated with xmlMalloc/xmlRealloc.
           Free only the array (the xmlNs pointers are not owned by the caller). */
        xmlFree(nslist);
        nslist = NULL;
    }

    /* Free the parsed document */
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here; leave global cleanup to process teardown. */
    return 0;
}