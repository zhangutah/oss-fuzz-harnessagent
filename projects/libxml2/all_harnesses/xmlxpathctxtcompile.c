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
// // xmlXPathCompExpr *
// //xmlXPathCompile(const xmlChar *str) {
// //    return(xmlXPathCtxtCompile(NULL, str));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlXPathCompExpr * xmlXPathCtxtCompile(xmlXPathContext * ctxt, const xmlChar * str);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for xmlXPathCtxtCompile
// Builds a null-terminated xmlChar string from the fuzzer input and calls
// xmlXPathCtxtCompile both with a created context and with NULL to exercise
// both code paths. Cleans up resources after use.
//
// To compile (example):
//   cc -O2 -g -fsanitize=address,fuzzer -I/path/to/libxml2/include \
//      fuzz_xmlxpathctxtcompile.c -lxml2 -o fuzz_xmlxpathctxtcompile
//
// Fuzzer entrypoint: LLVMFuzzerTestOneInput

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Make a null-terminated copy of the input as xmlChar* (unsigned char*) */
    xmlChar *input = (xmlChar *)malloc(Size + 1);
    if (input == NULL)
        return 0;
    memcpy(input, Data, Size);
    input[Size] = 0;

    /*
     * Case 1: Provide a real xmlXPathContext (created with NULL doc)
     * This exercises the branch where ctxt is not NULL.
     */
    xmlXPathContextPtr ctxt = xmlXPathNewContext(NULL);
    if (ctxt != NULL) {
        xmlXPathCompExprPtr comp = xmlXPathCtxtCompile(ctxt, input);
        if (comp != NULL) {
            /* free compiled expression if created */
            xmlXPathFreeCompExpr(comp);
        }
        xmlXPathFreeContext(ctxt);
    }

    /*
     * Case 2: Pass NULL for ctxt to exercise the internal creation path
     * inside xmlXPathCtxtCompile.
     */
    xmlXPathCompExprPtr comp2 = xmlXPathCtxtCompile(NULL, input);
    if (comp2 != NULL) {
        xmlXPathFreeCompExpr(comp2);
    }

    free(input);

    /*
     * Clean up parser global state (safe to call repeatedly).
     */
    xmlCleanupParser();

    return 0;
}
