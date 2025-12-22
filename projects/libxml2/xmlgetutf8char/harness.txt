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
// // const xmlChar *
// //xmlScanName(const xmlChar *ptr, size_t maxSize, int flags) {
// //    int stop = flags & XML_SCAN_NC ? ':' : 0;
// //    int old10 = flags & XML_SCAN_OLD10 ? 1 : 0;
// //
// //    while (1) {
// //        int c, len;
// //
// //        c = *ptr;
// //        if (c < 0x80) {
// //            if (c == stop)
// //                break;
// //            len = 1;
// //        } else {
// //            len = 4;
// //            c = xmlGetUTF8Char(ptr, &len);
// //            if (c < 0)
// //                break;
// //        }
// //
// //        if (flags & XML_SCAN_NMTOKEN ?
// //                !xmlIsNameChar(c, old10) :
// //                !xmlIsNameStartChar(c, old10))
// //            break;
// //
// //        if ((size_t) len > maxSize)
// //            return(NULL);
// //        ptr += len;
// //        maxSize -= len;
// //        flags |= XML_SCAN_NMTOKEN;
// //    }
// //
// //    return(ptr);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlGetUTF8Char(const unsigned char * utf, int * len);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Include the declaration for xmlGetUTF8Char.
   Use the absolute path discovered in the project. */
#include "/src/libxml2/include/libxml/xmlstring.h"

/*
 Fuzzer entry point.
 This harness exercises xmlGetUTF8Char() with a variety of inputs derived
 from the fuzzer-provided buffer.
*/
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Allocate a local buffer with a few extra bytes of padding so
       xmlGetUTF8Char can safely read up to 4 bytes from any start
       position within the copied data. */
    size_t copy_len = (Size > 0) ? Size : 0;
    size_t buf_size = copy_len + 4; /* ensure room for up to utf[3] access */
    unsigned char *buf = (unsigned char *)malloc(buf_size ? buf_size : 1);
    if (buf == NULL)
        return 0;

    if (copy_len > 0)
        memcpy(buf, Data, copy_len);
    /* Zero pad the extra bytes to avoid out-of-bounds reads triggering UB. */
    if (buf_size > copy_len)
        memset(buf + copy_len, 0, buf_size - copy_len);

    /* A set of len values to test various code paths (including too-small buffers). */
    int test_lens[] = { 0, 1, 2, 3, 4, 5, 10, INT_MAX, -1 };
    const size_t n_test_lens = sizeof(test_lens) / sizeof(test_lens[0]);

    /* If we have data, test starting at several offsets (0..3) within it so we
       exercise multi-byte sequences and boundary conditions. If Size == 0,
       we'll still call with a zeroed buffer below to exercise the error handling. */
    if (copy_len > 0) {
        size_t max_start = copy_len >= 4 ? 4 : copy_len;
        for (size_t start = 0; start < max_start; ++start) {
            unsigned char *p = buf + start;
            for (size_t i = 0; i < n_test_lens; ++i) {
                int l = test_lens[i];
                /* Call and ignore the return value; we only want to ensure no UB/crash. */
                (void)xmlGetUTF8Char(p, &l);
                /* Also try with very large 'len' to exercise other checks. */
                int large_len = INT_MAX;
                (void)xmlGetUTF8Char(p, &large_len);
            }
        }
    }

    /* Also test starting at the beginning of the buffer (works even when Size==0). */
    for (size_t i = 0; i < n_test_lens; ++i) {
        int l = test_lens[i];
        (void)xmlGetUTF8Char(buf, &l);
    }

    /* Exercise the error-handling paths explicitly:
       - utf == NULL (should return -1 and set *len to 0 when len != NULL)
       - len == NULL (should return -1)
    */
    {
        int l = 1;
        (void)xmlGetUTF8Char(NULL, &l); /* utf NULL */
        (void)xmlGetUTF8Char(buf, NULL); /* len NULL */
    }

    free(buf);
    return 0;
}