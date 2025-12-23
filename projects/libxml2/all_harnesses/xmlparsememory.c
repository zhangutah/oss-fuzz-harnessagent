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
//     xmlDoc * xmlParseMemory(const char * buffer, int size);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     xmlDoc * xmlParseMemory(const char * buffer, int size);
// Fuzzer entry point:
//     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// Full standalone C driver:

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>

// Include libxml2 headers (project absolute paths provided by the workspace)
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

// Suppress libxml error output to avoid noisy logs during fuzzing.
static void libxml_noop_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
    // Intentionally empty: we don't want libxml to print errors to stderr during fuzzing.
}

// Initialize libxml parser once per process.
__attribute__((constructor)) static void fuzz_libxml_init(void)
{
    // Initialize the library and check potential ABI mismatches.
    xmlInitParser();

    // Disable default error output.
    xmlSetGenericErrorFunc(NULL, libxml_noop_error);

    // Optionally: disable entity substitution and network access by default if needed.
    // Many libxml installations allow setting parser options globally; however xmlParseMemory
    // uses SAX parser without explicit options. Keeping initialization minimal here.
}

// Cleanup libxml parser at process exit.
__attribute__((destructor)) static void fuzz_libxml_deinit(void)
{
    xmlCleanupParser();
}

// Fuzzer entry point required by libFuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Data == NULL) return 0;

    // xmlParseMemory takes an 'int' size. Guard against very large sizes.
    int int_size;
    if (Size > (size_t)INT_MAX) {
        int_size = INT_MAX;
    } else {
        int_size = (int)Size;
    }

    // xmlParseMemory does not require a NUL-terminated buffer; pass raw data directly.
    // Cast away const-ness to match signature (xmlParseMemory expects const char*).
    xmlDoc *doc = xmlParseMemory((const char *)Data, int_size);

    if (doc != NULL) {
        // Free the parsed document to avoid memory leaks between runs.
        xmlFreeDoc(doc);
    }

    // Return 0 per libFuzzer convention.
    return 0;
}
