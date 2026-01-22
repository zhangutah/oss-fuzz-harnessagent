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
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     ssize_t phr_decode_chunked(struct phr_chunked_decoder * decoder, char * buf, size_t * bufsz);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>
#include <sys/types.h>

// Include picohttpparser header (absolute path provided by project)
#include "/src/mosquitto/deps/picohttpparser/picohttpparser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimal guard
    if (Data == nullptr) return 0;

    // Initialize decoder to a sane initial state
    struct phr_chunked_decoder decoder;
    std::memset(&decoder, 0, sizeof(decoder));
    decoder.bytes_left_in_chunk = 0;
    decoder.consume_trailer = 1; // allow consuming trailers
    decoder._hex_count = 0;
    decoder._state = 0; // CHUNKED_IN_CHUNK_SIZE (enum starts at 0 in implementation)

    // Copy input into a mutable buffer as phr_decode_chunked modifies it
    std::vector<char> buf;
    if (Size > 0) {
        buf.resize(Size);
        std::memcpy(buf.data(), Data, Size);
    } else {
        // Provide at least a small buffer to avoid passing nullptr
        buf.resize(1);
        buf[0] = 0;
    }

    size_t bufsz = buf.size();

    // Single-shot invocation
    ssize_t ret = phr_decode_chunked(&decoder, buf.data(), &bufsz);
    (void)ret; // ignore result, fuzzer observes crashes/UB

    // Also exercise incremental feeding: feed the data in small chunks to simulate streaming
    // Reset decoder and use small incremental slices
    std::memset(&decoder, 0, sizeof(decoder));
    decoder.consume_trailer = 1;
    decoder._state = 0;
    decoder.bytes_left_in_chunk = 0;
    decoder._hex_count = 0;

    // Split the input into several progressive chunks and call the decoder repeatedly.
    // This can expose state-machine related issues.
    size_t offset = 0;
    size_t remaining = buf.size();
    while (remaining > 0) {
        // choose a small chunk size (at least 1)
        size_t chunk = remaining < 4 ? remaining : (remaining / 4);
        if (chunk == 0) chunk = 1;

        // prepare chunk buffer (mutable)
        std::vector<char> chunkbuf(chunk);
        std::memcpy(chunkbuf.data(), buf.data() + offset, chunk);
        size_t chunk_sz = chunk;

        ssize_t r2 = phr_decode_chunked(&decoder, chunkbuf.data(), &chunk_sz);
        (void)r2;

        // advance
        offset += chunk;
        remaining -= chunk;
    }

    // Optionally call helper to exercise API that checks decoder state
    int in_data = phr_decode_chunked_is_in_data(&decoder);
    (void)in_data;

    return 0;
}