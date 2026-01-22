// Generate a fuzz driver based the given function signature in CPP language. 
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
// // int phr_parse_request(const char *buf_start, size_t len, const char **method, size_t *method_len, const char **path,
// //                      size_t *path_len, int *minor_version, struct phr_header *headers, size_t *num_headers, size_t last_len)
// //{
// //    const char *buf = buf_start, *buf_end = buf_start + len;
// //    size_t max_headers = *num_headers;
// //    int r;
// //
// //    *method = NULL;
// //    *method_len = 0;
// //    *path = NULL;
// //    *path_len = 0;
// //    *minor_version = -1;
// //    *num_headers = 0;
// //
// //    /* if last_len != 0, check if the request is complete (a fast countermeasure
// //       againt slowloris */
// //    if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
// //        return r;
// //    }
// //
// //    if ((buf = parse_request(buf, buf_end, method, method_len, path, path_len, minor_version, headers, num_headers, max_headers,
// //                             &r)) == NULL) {
// //        return r;
// //    }
// //
// //    return (int)(buf - buf_start);
// //}
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     const char * parse_request(const char * buf, const char * buf_end, const char ** method, size_t * method_len, const char ** path, size_t * path_len, int * minor_version, struct phr_header * headers, size_t * num_headers, size_t max_headers, int * ret);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
// Fuzz driver for parse_request (wrapped via picohttpparser)
// This driver is C++ and implements the fuzzer entry point:
//   extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
//
// Strategy:
// - Include the picohttpparser implementation into this translation unit so that
//   the static function `parse_request` is available for direct invocation.
// - Prepare the arguments expected by parse_request, with a fixed-size header array.
// - Call parse_request and exercise its outputs lightly (copying method/path/header
//   strings bounded by the input size) to avoid UB while letting sanitizer catches
//   problems inside parse_request itself.
//
// Note: Adjust the include path if your build system places picohttpparser sources elsewhere.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <string>

// Include the public header (for struct phr_header definition)
#include "deps/picohttpparser/picohttpparser.h"

// Include the implementation to gain access to the static parse_request function.
// Path used here is relative to the project root; change if necessary.
extern "C" {
#include "deps/picohttpparser/picohttpparser.c"
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Defensive: allow empty input (parse_request will normally return NULL / error)
    const char *buf = reinterpret_cast<const char *>(Data);
    const char *buf_end = buf + Size;

    // Prepare outputs expected by parse_request
    const char *method = nullptr;
    size_t method_len = 0;
    const char *path = nullptr;
    size_t path_len = 0;
    int minor_version = -1;

    // Prepare headers buffer. Choose a modest fixed bound.
    constexpr size_t MAX_HEADERS = 64;
    struct phr_header headers[MAX_HEADERS];
    // Initialize headers to zero to avoid uninitialized reads in case of early exit
    for (size_t i = 0; i < MAX_HEADERS; ++i) {
        headers[i].name = nullptr;
        headers[i].name_len = 0;
        headers[i].value = nullptr;
        headers[i].value_len = 0;
    }
    size_t num_headers = MAX_HEADERS;
    int ret = 0;

    // Call the target function.
    // parse_request signature:
    // const char * parse_request(const char * buf, const char * buf_end,
    //                            const char ** method, size_t * method_len,
    //                            const char ** path, size_t * path_len,
    //                            int * minor_version, struct phr_header * headers,
    //                            size_t * num_headers, size_t max_headers, int * ret);
    const char *res = parse_request(buf, buf_end,
                                    &method, &method_len,
                                    &path, &path_len,
                                    &minor_version,
                                    headers, &num_headers, MAX_HEADERS,
                                    &ret);

    // Lightly exercise returned pointers in a safe manner to avoid sanitizer false positives:
    // - Only construct strings up to Size bytes.
    // - Protect against suspicious lengths by clamping to Size.
    if (method != nullptr && method_len > 0) {
        size_t ml = std::min(method_len, Size);
        // Ensure the pointer is within the provided buffer range before constructing string.
        if (method >= buf && method + ml <= buf_end) {
            std::string s_method(method, ml);
            (void)s_method.size(); // use it to avoid optimizing away
        }
    }

    if (path != nullptr && path_len > 0) {
        size_t pl = std::min(path_len, Size);
        if (path >= buf && path + pl <= buf_end) {
            std::string s_path(path, pl);
            (void)s_path.size();
        }
    }

    // Iterate returned headers (num_headers set by parse_request) but clamp to MAX_HEADERS
    size_t hdr_count = std::min(num_headers, MAX_HEADERS);
    for (size_t i = 0; i < hdr_count; ++i) {
        const char *n = headers[i].name;
        size_t nlen = headers[i].name_len;
        const char *v = headers[i].value;
        size_t vlen = headers[i].value_len;

        // Only copy small amounts (bounded by Size) and ensure pointers lie inside the input buffer.
        if (n != nullptr && nlen > 0) {
            size_t nlen_clamped = std::min(nlen, Size);
            if (n >= buf && n + nlen_clamped <= buf_end) {
                std::string name(n, nlen_clamped);
                (void)name.size();
            }
        }
        if (v != nullptr && vlen > 0) {
            size_t vlen_clamped = std::min(vlen, Size);
            if (v >= buf && v + vlen_clamped <= buf_end) {
                std::string value(v, vlen_clamped);
                (void)value.size();
            }
        }
    }

    // Use other outputs to avoid unused warnings
    (void)res;
    (void)minor_version;
    (void)ret;

    return 0;
}