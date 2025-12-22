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
//     int xmlSAXUserParseMemory(xmlSAXHandler * sax, void * user_data, const char * buffer, int size);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmlSAXUserParseMemory(xmlSAXHandler * sax, void * user_data, const char * buffer, int size);
//
// Fuzzer entry point:
//   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

// Prefer absolute project header as provided by the helper tool:
#include "/src/libxml2/include/libxml/parser.h"

// If the absolute include above does not work in your build environment,
// you may need to replace it with: #include <libxml/parser.h>

// Initialize libxml2 once.
static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        /* Optionally suppress libxml2 error output to stderr during fuzzing: */
        xmlSetGenericErrorFunc(NULL, NULL);
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data)
        return 0;

    ensure_libxml_initialized();

    // xmlSAXUserParseMemory expects an int size; clamp to INT_MAX to be safe.
    if (Size > (size_t)INT_MAX)
        Size = (size_t)INT_MAX;
    int size = (int)Size;

    // Allocate a buffer with an extra byte for a terminating NUL. Some codepaths
    // may expect NUL termination even if a length is provided.
    char *buf = (char *)malloc((size_t)size + 1);
    if (!buf)
        return 0;

    if (size > 0)
        memcpy(buf, Data, (size_t)size);
    buf[size] = '\0';

    // Call the API under test. Use NULL SAX handler and NULL user_data so the
    // library uses its default SAX callbacks.
    // We intentionally ignore the return value.
    xmlSAXUserParseMemory(NULL, NULL, buf, size);

    free(buf);
    return 0;
}