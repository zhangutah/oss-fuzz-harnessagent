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
//     xmlDoc * xmlRecoverMemory(const char * buffer, int size);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

/* Include the libxml2 parser header (project absolute path as returned by repo tools) */
#include "/src/libxml2/include/libxml/parser.h"

/* Silence libxml2 error output to keep fuzzer logs clean */
static void silent_libxml_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

/* Ensure libxml is initialized once and cleaned up at program exit */
static void ensure_libxml_initialized(void)
{
    static int initialized = 0;
    if (initialized)
        return;

    xmlInitParser();
    /* Set a no-op error handler to avoid noisy stderr output from libxml */
    xmlSetGenericErrorFunc(NULL, (xmlGenericErrorFunc)silent_libxml_error);
    /* Register cleanup at exit */
    atexit(xmlCleanupParser);

    initialized = 1;
}

/* Fuzzer entry point required by many fuzzing frameworks (libFuzzer) */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    ensure_libxml_initialized();

    if (Data == NULL || Size == 0)
        return 0;

    /* xmlRecoverMemory takes an int for size; clamp to INT_MAX */
    int size_int = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Call the target function with the fuzzer provided data */
    xmlDocPtr doc = xmlRecoverMemory((const char *)Data, size_int);

    /* If a document was returned, free it to avoid leaks across runs */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    return 0;
}
