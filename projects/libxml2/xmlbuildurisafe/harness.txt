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
// // xmlChar *
// //xmlBuildURI(const xmlChar *URI, const xmlChar *base) {
// //    xmlChar *out;
// //
// //    xmlBuildURISafe(URI, base, &out);
// //    return(out);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlBuildURISafe(const xmlChar * URI, const xmlChar * base, xmlChar ** out);
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

/* Project headers (absolute paths as reported by the project) */
#include "/src/libxml2/include/libxml/uri.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzzer entry point for fuzzing:
     int xmlBuildURISafe(const xmlChar *URI, const xmlChar *base, xmlChar **out);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Nothing to do for empty input */
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser state (safe to call multiple times) */
    xmlInitParser();

    /*
      Split the fuzzer input into two parts:
      - the first part is used as URI
      - the second part (possibly empty) is used as base
      If the base part is empty, pass NULL to exercise that code path.
    */
    size_t split = Size / 2;
    if (split == 0)
        split = Size; /* If Size == 1, put everything into URI and base will be NULL */

    size_t uri_len = split;
    size_t base_len = (Size > split) ? (Size - split) : 0;

    /* Allocate and NUL-terminate the copies as xmlChar* (typedef unsigned char) */
    unsigned char *uri_buf = (unsigned char *)malloc(uri_len + 1);
    if (uri_buf == NULL)
        return 0;
    memcpy(uri_buf, Data, uri_len);
    uri_buf[uri_len] = '\0';

    unsigned char *base_buf = NULL;
    if (base_len > 0) {
        base_buf = (unsigned char *)malloc(base_len + 1);
        if (base_buf == NULL) {
            free(uri_buf);
            return 0;
        }
        memcpy(base_buf, Data + split, base_len);
        base_buf[base_len] = '\0';
    }

    const xmlChar *uri = (const xmlChar *)uri_buf;
    const xmlChar *base = (base_buf != NULL) ? (const xmlChar *)base_buf : NULL;
    xmlChar *out = NULL;

    /* Call the target function under test */
    (void)xmlBuildURISafe(uri, base, &out);

    /* Free any allocated output from the library */
    if (out != NULL)
        xmlFree(out);

    /* Free our temporary buffers */
    free(uri_buf);
    if (base_buf != NULL)
        free(base_buf);

    /* Note: xmlCleanupParser() is omitted to avoid tearing down parser state every run.
       It can be called at process shutdown if desired. */

    return 0;
}
