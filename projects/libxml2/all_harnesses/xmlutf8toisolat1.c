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
//     int xmlUTF8ToIsolat1(unsigned char * out, int * outlen, const unsigned char * in, int * inlen);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>

/* Include the header that declares xmlUTF8ToIsolat1.
   Using the absolute path returned by project lookup. */
#include "/src/libxml2/include/libxml/encoding.h"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Cap allocations to avoid huge memory usage from large Size inputs. */
    const size_t MAX_OUT_CAP = 1000000; /* 1 MB cap */
    size_t desired_out = (Size > (MAX_OUT_CAP/2)) ? MAX_OUT_CAP : (Size * 2 + 10);
    int out_buf_size = (desired_out > (size_t)INT_MAX) ? INT_MAX : (int)desired_out;

    unsigned char *out = (unsigned char*)malloc((size_t)out_buf_size);
    if (out == NULL) return 0;

    /* xmlUTF8ToIsolat1 expects int * for lengths. Clamp Size to INT_MAX. */
    int inlen = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    int outlen = out_buf_size;

    /* Call the function under test. The input pointer types are compatible. */
    int rc = xmlUTF8ToIsolat1(out, &outlen, (const unsigned char *)Data, &inlen);

    /* Use the output in a small, harmless way to prevent aggressive optimizers
       from removing the call. */
    if (outlen > 0 && out != NULL) {
        volatile unsigned char sink = out[0];
        (void)sink;
    }

    (void)rc; /* ignore return value for the fuzzer harness */

    free(out);
    return 0;
}
