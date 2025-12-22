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
//     xmlDoc * htmlParseDoc(const xmlChar * cur, const char * encoding);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     xmlDoc * htmlParseDoc(const xmlChar * cur, const char * encoding);
// Fuzzer entry point:
//     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Use absolute project headers as discovered */
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/* Initialize libxml2 once per process and register cleanup at exit. */
static void ensure_libxml_initialized(void) {
    static int inited = 0;
    if (!inited) {
        /* xmlInitParser is safe to call multiple times but we call it once. */
        xmlInitParser();
        /* xmlCleanupParser should be called at process exit, not per input. */
        atexit(xmlCleanupParser);
        inited = 1;
    }
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ensure_libxml_initialized();

    /* Allocate a nul-terminated buffer since htmlParseDoc expects a string */
    size_t buf_size = Size + 1;
    unsigned char *buf = (unsigned char *)malloc(buf_size);
    if (!buf) return 0;

    if (Size > 0) memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Call the function under test. Pass NULL for encoding (optional). */
    xmlDoc *doc = htmlParseDoc((const xmlChar *)buf, NULL);

    /* Free the resulting document if created. */
    if (doc) xmlFreeDoc(doc);

    free(buf);
    return 0;
}