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
// // int phr_parse_response(const char *buf_start, size_t len, int *minor_version, int *status, const char **msg, size_t *msg_len,
// //                       struct phr_header *headers, size_t *num_headers, size_t last_len)
// //{
// //    const char *buf = buf_start, *buf_end = buf + len;
// //    size_t max_headers = *num_headers;
// //    int r;
// //
// //    *minor_version = -1;
// //    *status = 0;
// //    *msg = NULL;
// //    *msg_len = 0;
// //    *num_headers = 0;
// //
// //    /* if last_len != 0, check if the response is complete (a fast countermeasure
// //       against slowloris */
// //    if (last_len != 0 && is_complete(buf, buf_end, last_len, &r) == NULL) {
// //        return r;
// //    }
// //
// //    if ((buf = parse_response(buf, buf_end, minor_version, status, msg, msg_len, headers, num_headers, max_headers, &r)) == NULL) {
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
//     const char * parse_response(const char * buf, const char * buf_end, int * minor_version, int * status, const char ** msg, size_t * msg_len, struct phr_header * headers, size_t * num_headers, size_t max_headers, int * ret);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>

// Include the picohttpparser implementation so we can call its (static) parse_response function directly.
// Using the absolute path returned from the project workspace.
#include "/src/mosquitto/deps/picohttpparser/picohttpparser.c"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Treat the fuzz input as the HTTP buffer to parse.
    const char *buf_start = reinterpret_cast<const char *>(Data);
    const char *buf_end = buf_start + Size;

    // Prepare outputs expected by parse_response.
    int minor_version = 0;
    int status = 0;
    const char *msg = nullptr;
    size_t msg_len = 0;

    // Choose a reasonable maximum number of headers to allocate.
    // Use a small cap to avoid excessive allocations for large fuzz inputs.
    const size_t kMaxHeadersCap = 256;
    size_t max_headers = std::min<std::size_t>(kMaxHeadersCap, Size > 0 ? Size : 1);

    // Allocate headers array.
    struct phr_header *headers = nullptr;
    if (max_headers > 0) {
        headers = (struct phr_header *)malloc(sizeof(struct phr_header) * max_headers);
        if (!headers) {
            return 0;
        }
    }

    // num_headers should contain the capacity on input and will be set to the parsed count on output.
    size_t num_headers = max_headers;

    int ret = 0;

    // Call the function under test.
    // parse_response returns a pointer into the buffer on success or NULL on error/partial.
    const char *res = parse_response(buf_start, buf_end, &minor_version, &status, &msg, &msg_len, headers, &num_headers, max_headers, &ret);

    // Touch some of the outputs to ensure the compiler doesn't optimize away the call.
    if (res) {
        // compute consumed length safely
        size_t consumed = 0;
        if (res >= buf_start && res <= buf_end) consumed = static_cast<size_t>(res - buf_start);
        // read a byte at res if within range
        if (res >= buf_start && (res < buf_end)) {
            volatile char c = res[0];
            (void)c;
        }
        (void)consumed;
    } else {
        // touch ret and status/minor_version/msg/msg_len/num_headers
        volatile int vret = ret;
        volatile int vstatus = status;
        volatile int vminor = minor_version;
        volatile size_t vmsglen = msg_len;
        volatile size_t vnumhdr = num_headers;
        (void)vret; (void)vstatus; (void)vminor; (void)vmsglen; (void)vnumhdr;
        if (msg && msg_len > 0) {
            // safely read first byte of msg if possible
            volatile char c = msg[0];
            (void)c;
        }
    }

    free(headers);
    return 0;
}
