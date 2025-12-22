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
// // xmlDoc *
// //xmlSAXParseMemory(xmlSAXHandler *sax, const char *buffer,
// //	          int size, int recovery) {
// //    return xmlSAXParseMemoryWithData(sax, buffer, size, recovery, NULL);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlSAXParseMemoryWithData(xmlSAXHandler * sax, const char * buffer, int size, int recovery, void * data);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     xmlDoc * xmlSAXParseMemoryWithData(xmlSAXHandler * sax, const char * buffer, int size, int recovery, void * data);
// Fuzzer entry point:
//     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
//
/*
  This driver:
  - Includes the libxml2 parser header.
  - Initializes the parser once.
  - Installs a no-op error handler to avoid noisy output during fuzzing.
  - Copies input into a null-terminated buffer (safe) and calls xmlSAXParseMemoryWithData.
  - Frees any produced document and temporary memory.
*/

#include "/src/libxml2/include/libxml/parser.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

/* No-op generic error handler to suppress libxml2 error output during fuzzing */
static void silent_xml_error(void *ctx, const char *msg, ...) {
    (void)ctx;
    (void)msg;
}

/* LLVMFuzzerTestOneInput entrypoint for libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* Initialize libxml2 parser once */
        xmlInitParser();
        /* Redirect libxml2 errors to our silent handler */
        xmlSetGenericErrorFunc(NULL, (xmlGenericErrorFunc)silent_xml_error);
        inited = 1;
    }

    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* Ensure we don't overflow int when casting size */
    int buf_size;
    if (Size > (size_t)(INT_MAX - 1)) {
        buf_size = INT_MAX - 1;
    } else {
        buf_size = (int)Size;
    }

    /* Copy input and ensure null-termination for safety */
    char *buffer = (char *)malloc((size_t)buf_size + 1);
    if (!buffer) return 0;
    memcpy(buffer, Data, (size_t)buf_size);
    buffer[buf_size] = '\0';

    /* Call the target function. Use NULL SAX handler (allow default behavior),
       recovery = 0 (no recovery), data = NULL. */
    xmlDoc *doc = xmlSAXParseMemoryWithData(NULL, buffer, buf_size, 0, NULL);

    /* Free produced document if any */
    if (doc) {
        xmlFreeDoc(doc);
    }

    free(buffer);

    /* Do not call xmlCleanupParser() here 	6 calling it repeatedly can
       interfere with subsequent fuzzing iterations. */

    return 0;
}
