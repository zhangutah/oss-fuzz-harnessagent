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
//     xmlDoc * htmlReadMemory(const char * buffer, int size, const char * URL, const char * encoding, int options);
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
#include <limits.h>

/* Use the header discovered for htmlReadMemory */
#include "/src/libxml2/include/libxml/HTMLparser.h"

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* Initialize the libxml2 parser once */
        xmlInitParser();
        inited = 1;
    }

    /* Normalize Size to an int for the htmlReadMemory call, avoid overflow. */
    int bufSize;
    if (Size > (size_t)(INT_MAX - 1)) {
        bufSize = INT_MAX - 1;
    } else {
        bufSize = (int)Size;
    }

    /* Allocate a buffer and ensure it is NUL-terminated for safety */
    char *buf = (char *)malloc((size_t)bufSize + 1);
    if (!buf)
        return 0;

    if (Size > 0) {
        memcpy(buf, Data, (size_t)bufSize);
    }
    buf[bufSize] = '\0';

    /* Derive URL, encoding and options from the input bytes (if available) */
    const char *url = NULL;
    const char *encoding = NULL;
    int options = 0;

    if (Size > 0) {
        uint8_t b0 = Data[0];
        switch (b0 & 3) {
            case 0: url = NULL; break;
            case 1: url = "http://example.com/"; break;
            case 2: url = "file:///tmp/fuzz.html"; break;
            default: url = "about:blank"; break;
        }
        switch ((b0 >> 2) & 3) {
            case 0: encoding = NULL; break;
            case 1: encoding = "UTF-8"; break;
            case 2: encoding = "ISO-8859-1"; break;
            default: encoding = "ASCII"; break;
        }
        if (Size > 1) {
            /* Keep options in a reasonable range */
            options = (int)(Data[1]) & 0xFFFF;
        }
    }

    /* Call the target function */
    xmlDoc *doc = htmlReadMemory((const char *)buf, bufSize, url, encoding, options);

    /* Clean up */
    if (doc)
        xmlFreeDoc(doc);

    free(buf);

    return 0;
}
