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
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlNode * xmlTextMerge(xmlNode * first, xmlNode * second);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlNode * xmlTextMerge(xmlNode * first, xmlNode * second);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Note: Includes attempt absolute project headers as requested.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Prefer absolute project headers first (as returned by analysis tools).
   If building outside that layout, the normal libxml2 headers (<libxml/tree.h>, <libxml/parser.h>)
   should be used instead. */
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/parser.h"

/* Simple one-time initialization for the libxml2 library. */
static int libxml_inited = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser once (safe to call repeatedly but do it once). */
    if (!libxml_inited) {
        xmlInitParser();
        libxml_inited = 1;
    }

    /* Split the input into two parts to build two text nodes. */
    size_t mid = Size / 2;
    size_t len1 = mid;
    size_t len2 = Size - mid;

    /* Allocate temporary null-terminated buffers for xmlNewText (it uses xmlStrdup). */
    xmlChar *buf1 = NULL;
    xmlChar *buf2 = NULL;

    if (len1 > 0) {
        buf1 = (xmlChar *)malloc(len1 + 1);
        if (buf1 == NULL) goto cleanup;
        memcpy(buf1, Data, len1);
        buf1[len1] = '\0';
    }

    if (len2 > 0) {
        buf2 = (xmlChar *)malloc(len2 + 1);
        if (buf2 == NULL) goto cleanup;
        memcpy(buf2, Data + mid, len2);
        buf2[len2] = '\0';
    }

    /* Create text nodes. xmlNewText duplicates the content. */
    xmlNode *node1 = NULL;
    xmlNode *node2 = NULL;

    node1 = xmlNewText(buf1);
    node2 = xmlNewText(buf2);

    /* Call the target function under test. */
    xmlNode *merged = xmlTextMerge(node1, node2);

    /* Free nodes safely:
       - On success merged == node1, and node2 has been unlinked & freed by xmlTextMerge.
       - If merged == NULL, xmlTextMerge didn't free nodes (in the code paths used here),
         so free any non-NULL nodes we still own.
       - Otherwise (if xmlTextMerge returned node2 because node1 was NULL), free accordingly.
    */
    if (merged == NULL) {
        if (node1 != NULL) xmlFreeNode(node1);
        if (node2 != NULL) xmlFreeNode(node2);
    } else {
        /* merged points to whichever node survived; free it. */
        xmlFreeNode(merged);
    }

cleanup:
    if (buf1) { free(buf1); buf1 = NULL; }
    if (buf2) { free(buf2); buf2 = NULL; }

    /* Do not call xmlCleanupParser here; calling it too early can lead to
       reinitialization issues if the fuzzer runs multiple testcases in the
       same process. */

    return 0;
}
