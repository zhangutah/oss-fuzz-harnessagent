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
//     xmlParserCtxt * xmlCreateEntityParserCtxt(const xmlChar * URL, const xmlChar * ID, const xmlChar * base);
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

/* Use the project header that declares xmlCreateEntityParserCtxt */
#include "/src/libxml2/include/libxml/parserInternals.h"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* Initialize libxml parser once */
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Split the input into three parts for URL, ID and base */
    size_t part1 = Size / 3;
    size_t part2 = (Size - part1) / 2;
    size_t part3 = Size - part1 - part2;

    /* Allocate and null-terminate the three strings */
    char *s1 = (char *)malloc(part1 + 1);
    char *s2 = (char *)malloc(part2 + 1);
    char *s3 = (char *)malloc(part3 + 1);

    if (!s1 || !s2 || !s3) {
        free(s1);
        free(s2);
        free(s3);
        return 0;
    }

    if (part1) memcpy(s1, Data, part1);
    s1[part1] = '\0';
    if (part2) memcpy(s2, Data + part1, part2);
    s2[part2] = '\0';
    if (part3) memcpy(s3, Data + part1 + part2, part3);
    s3[part3] = '\0';

    /* Call the target API */
    xmlParserCtxt *ctxt = xmlCreateEntityParserCtxt((const xmlChar *)s1,
                                                    (const xmlChar *)s2,
                                                    (const xmlChar *)s3);

    /* If a context was created, free it to avoid leaks */
    if (ctxt) {
        /* xmlFreeParserCtxt is provided by libxml2 to free parser contexts */
        xmlFreeParserCtxt(ctxt);
    }

    free(s1);
    free(s2);
    free(s3);

    return 0;
}