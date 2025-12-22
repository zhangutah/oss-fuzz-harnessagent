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
// // static xmlCharEncError
// //UTF8ToHtmlWrapper(void *vctxt ATTRIBUTE_UNUSED,
// //                  unsigned char *out, int *outlen,
// //                  const unsigned char *in, int *inlen,
// //                  int flush ATTRIBUTE_UNUSED) {
// //    return(htmlUTF8ToHtml(out, outlen, in, inlen));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int htmlUTF8ToHtml(unsigned char * out, int * outlen, const unsigned char * in, int * inlen);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzzer driver for:
//   int htmlUTF8ToHtml(unsigned char * out, int * outlen, const unsigned char * in, int * inlen);

// Fuzzer entry point:
//   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

// This file calls htmlUTF8ToHtml with a variety of buffer sizes and input conditions
// to exercise common code paths (normal conversion, insufficient output space,
// and the in==NULL initialization path).

// Include the header that declares htmlUTF8ToHtml. If your build system places the
// libxml2 headers elsewhere, update the include path accordingly.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>

/* Absolute include path discovered in the workspace. Update if necessary. */
#include "/src/libxml2/include/libxml/HTMLparser.h"

/* Fuzzer entry point called by libFuzzer/LLVM fuzzer harness. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic guard: accept zero-length inputs quickly */
    if (Data == NULL)
        return 0;

    /* Convert Size to int safely for the API which uses int for lengths. */
    int inlen = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    const unsigned char *in = (const unsigned char *)Data;

    /* Allocate an output buffer sized to accommodate entity expansion.
       Heuristic: worst-case expansion ~10x per byte plus some slack. */
    size_t outbuf_sz_s = (size_t)inlen * 10 + 16;
    if (outbuf_sz_s > (size_t)INT_MAX)
        outbuf_sz_s = (size_t)INT_MAX;
    int outbuf_sz = (int)outbuf_sz_s;

    unsigned char *outbuf = (unsigned char *)malloc((size_t)outbuf_sz);
    if (outbuf == NULL) {
        /* allocation failed; nothing to do */
        return 0;
    }

    /* Normal call: provide a reasonably large output buffer */
    {
        int outlen = outbuf_sz;
        int inlen_copy = inlen;
        /* Call the target function */
        (void) htmlUTF8ToHtml(outbuf, &outlen, in, &inlen_copy);
        /* Optionally touch output to avoid optimizing away (not required for fuzzers) */
        if (outlen > 0 && outlen <= outbuf_sz) {
            volatile unsigned char sink = outbuf[0];
            (void)sink;
        }
    }

    /* Call with intentionally small output space to exercise the 'space' handling path */
    if (outbuf_sz > 4) {
        int small_outlen = 1; /* too small to hold many expansions */
        int inlen_copy = inlen;
        /* Use the same buffer (only first byte available) */
        (void) htmlUTF8ToHtml(outbuf, &small_outlen, in, &inlen_copy);
    }

    /* Call with in == NULL to exercise initialization path where the function
       sets *outlen = 0 and *inlen = 0 and returns success (provided out & pointers non-NULL). */
    {
        unsigned char tiny_out[8];
        int tiny_outlen = sizeof(tiny_out);
        int inlen_for_null = 123; /* will be overwritten to 0 by the function */
        (void) htmlUTF8ToHtml(tiny_out, &tiny_outlen, NULL, &inlen_for_null);
    }

    free(outbuf);
    return 0;
}