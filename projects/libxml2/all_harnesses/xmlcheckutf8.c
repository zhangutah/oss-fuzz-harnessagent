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
// // static void
// //xmlCtxtCheckString(xmlDebugCtxtPtr ctxt, const xmlChar * str)
// //{
// //    if (str == NULL) return;
// //    if (ctxt->check) {
// //        if (!xmlCheckUTF8(str)) {
// //	    xmlDebugErr3(ctxt, XML_CHECK_NOT_UTF8,
// //			 "String is not UTF-8 %s", (const char *) str);
// //	}
// //    }
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlCheckUTF8(const unsigned char * utf);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: int xmlCheckUTF8(const unsigned char * utf);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Build note: Ensure libxml2 headers are available at the include path below
// (this uses the project-absolute header path returned by the project helper).
//
// This harness copies the fuzzer input into a NUL-terminated buffer before
// calling xmlCheckUTF8, because xmlCheckUTF8 expects a C-style string.
//
// Minimal standalone main is provided to allow running the harness with a file:
//    ./fuzz_driver inputfile
//
// The primary entrypoint for libFuzzer is LLVMFuzzerTestOneInput.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Project header that declares xmlCheckUTF8 */
#include "/src/libxml2/include/libxml/xmlstring.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Avoid unbounded allocations from very large inputs in case fuzzer driver
       runs outside of a proper harness environment. Adjust threshold as needed. */
    const size_t MAX_COPY = 10 * 1024 * 1024; /* 10 MB */
    if (Size > MAX_COPY) {
        /* Skip overly large cases */
        return 0;
    }

    /* Allocate a NUL-terminated buffer and copy the input */
    unsigned char *buf = (unsigned char *)malloc(Size + 1);
    if (buf == NULL) return 0;
    if (Size > 0) memcpy(buf, Data, Size);
    buf[Size] = 0; /* ensure NUL-termination */

    /* Call the target function. Use volatile to prevent optimization away. */
    volatile int rc = xmlCheckUTF8(buf);

    /* Use rc in a no-op manner to silence unused warnings (volatile kept it alive). */
    (void)rc;

    free(buf);
    return 0;
}

/* Optional standalone runner: read a file and pass contents to the fuzzer entry. */
#ifdef FUZZ_DRIVER_MAIN
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 1; }

    size_t size = (size_t)sz;
    uint8_t *data = (uint8_t *)malloc(size ? size : 1);
    if (!data) { fclose(f); return 1; }
    if (size > 0) {
        if (fread(data, 1, size, f) != size) { free(data); fclose(f); return 1; }
    }
    fclose(f);

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    return 0;
}
#endif

// To compile with standalone main enabled, define FUZZ_DRIVER_MAIN when compiling:
// gcc -DFUZZ_DRIVER_MAIN -I/path/to/libxml2/include -o fuzz_driver fuzz_driver.c -lxml2