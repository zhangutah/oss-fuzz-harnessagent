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
// // int
// //htmlIsAutoClosed(xmlDoc *doc, xmlNode *elem) {
// //    htmlNodePtr child;
// //
// //    if (elem == NULL) return(1);
// //    child = elem->children;
// //    while (child != NULL) {
// //	if (htmlAutoCloseTag(doc, elem->name, child)) return(1);
// //	child = child->next;
// //    }
// //    return(0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int htmlAutoCloseTag(xmlDoc * doc, const xmlChar * name, xmlNode * elem);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
// int htmlAutoCloseTag(xmlDoc * doc, const xmlChar * name, xmlNode * elem);
//
// Fuzzer entrypoint: LLVMFuzzerTestOneInput
//
// This driver constructs a small xmlDoc and xmlNode, derives the
// tag name and an optional attribute from the fuzzer input, calls
// htmlAutoCloseTag, then frees resources.
//
// Note: the header path below was obtained from the codebase. If building
// outside that environment, adjust includes to match your libxml2 install.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "/src/libxml2/include/libxml/HTMLparser.h"
#include <libxml/parser.h>
#include <libxml/tree.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser (safe to call multiple times) */
    xmlInitParser();

    /* Split Data into pieces:
     * - first part -> name (xmlChar*)
     * - remaining -> optional attribute name/value
     *
     * Cap lengths to avoid huge allocations.
     */
    size_t max_name = 1024;
    size_t half = Size / 2;
    if (half == 0) half = Size; /* if Size==1, use it for name */

    size_t name_len = half;
    if (name_len > max_name) name_len = max_name;

    /* ensure we don't read past Data */
    if (name_len > Size) name_len = Size;

    /* Create xmlChar * name (null-terminated) */
    xmlChar *name = xmlStrndup((const xmlChar *)Data, (int)name_len);
    if (name == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Prepare document and nodes */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        xmlFree(name);
        xmlCleanupParser();
        return 0;
    }

    /* Create a root element and attach to doc */
    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    if (root == NULL) {
        xmlFreeDoc(doc);
        xmlFree(name);
        xmlCleanupParser();
        return 0;
    }
    xmlDocSetRootElement(doc, root);

    /* Create the element to pass as 'elem' */
    xmlNodePtr elem = xmlNewNode(NULL, BAD_CAST "fuzznode");
    if (elem == NULL) {
        xmlFreeDoc(doc);
        xmlFree(name);
        xmlCleanupParser();
        return 0;
    }
    xmlAddChild(root, elem);

    /* Set the element name from fuzzer input (may be binary) */
    /* xmlNodeSetName expects const xmlChar* */
    xmlNodeSetName(elem, name);

    /* Optionally create an attribute from the remainder of Data to
       exercise more code paths (split remainder into attr name/value) */
    if (Size > name_len) {
        size_t rem = Size - name_len;
        const uint8_t *rem_ptr = Data + name_len;

        size_t an_len = rem / 2;
        size_t av_len = rem - an_len;
        if (an_len == 0 && av_len > 0) an_len = 1;
        if (av_len == 0 && an_len > 0) av_len = 1;
        if (an_len + av_len > rem) {
            /* adjust if rounding issues */
            if (an_len > rem) an_len = rem;
            av_len = rem - an_len;
        }

        xmlChar *attr_name = NULL;
        xmlChar *attr_val = NULL;

        if (an_len > 0) {
            attr_name = xmlStrndup((const xmlChar *)rem_ptr, (int)an_len);
        }
        if (av_len > 0) {
            attr_val = xmlStrndup((const xmlChar *)(rem_ptr + an_len), (int)av_len);
        }

        if (attr_name != NULL && attr_val != NULL) {
            /* set a property on elem; xmlSetProp makes a copy internally */
            xmlSetProp(elem, attr_name, attr_val);
        }

        if (attr_name) xmlFree(attr_name);
        if (attr_val) xmlFree(attr_val);
    }

    /* Call the target function */
    /* htmlAutoCloseTag prototype:
     * int htmlAutoCloseTag(xmlDoc * doc, const xmlChar * name, xmlNode * elem);
     */
    (void)htmlAutoCloseTag(doc, name, elem);

    /* Cleanup */
    xmlFreeDoc(doc);
    xmlFree(name);

    /* It's okay to call xmlCleanupParser here; some fuzz harnesses prefer not
     * to to retain parser state across runs, but calling it is safe. */
    xmlCleanupParser();

    return 0;
}
