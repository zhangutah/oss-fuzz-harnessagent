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
// //xmlCharStrdup(const char *cur) {
// //    const char *p = cur;
// //
// //    if (cur == NULL) return(NULL);
// //    while (*p != '\0') p++; /* non input consuming */
// //    return(xmlCharStrndup(cur, p - cur));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlChar * xmlCharStrndup(const char * cur, int len);
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

#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzzer entry point for:
     xmlChar * xmlCharStrndup(const char * cur, int len);

 This harness interprets the first up-to-4 bytes of the fuzzer input as a
 little-endian unsigned integer used to derive the 'len' argument (capped
 to a reasonable maximum). The remaining bytes (if any) are copied into
 a temporary, zero-padded buffer of size 'len' and passed as 'cur'. This
 prevents the target from reading beyond the provided buffer while still
 allowing a wide range of lengths and content to be tested.
*/

#ifndef MAX_FUZZ_LEN
#define MAX_FUZZ_LEN 4096
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Interpret up to first 4 bytes as little-endian integer for requested len */
    uint32_t raw_len = 0;
    size_t len_bytes = Size < 4 ? Size : 4;
    for (size_t i = 0; i < len_bytes; i++) {
        raw_len |= ((uint32_t)Data[i]) << (8 * i);
    }

    /* Cap length to avoid excessive allocations */
    int len = (int)(raw_len % (MAX_FUZZ_LEN + 1)); /* 0..MAX_FUZZ_LEN */

    /* Prepare a temporary buffer of size 'len' (zero-padded) to safely pass to the target */
    char *tmp = (char *)malloc((size_t)len + 1);
    if (tmp == NULL) return 0;
    memset(tmp, 0, (size_t)len + 1);

    /* Copy payload bytes (those after the length-specifier) into tmp, up to 'len' */
    if (Size > len_bytes && len > 0) {
        size_t payload_size = Size - len_bytes;
        size_t to_copy = (payload_size < (size_t)len) ? payload_size : (size_t)len;
        memcpy(tmp, Data + len_bytes, to_copy);
    }

    /* Call the target function */
    xmlChar *res = xmlCharStrndup((const char *)tmp, len);

    /* Free returned memory using xmlFree (matches xmlMalloc used by the implementation) */
    if (res != NULL) {
        xmlFree(res);
    }

    free(tmp);
    return 0;
}