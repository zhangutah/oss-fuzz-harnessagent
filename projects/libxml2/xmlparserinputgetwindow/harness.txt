#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Use the real libxml2 headers so the struct layouts match the library.
#ifdef __cplusplus
extern "C" {
#endif

#include <libxml/parser.h>   // provides xmlParserInput and xmlParserInputGetWindow
#include <libxml/xmlstring.h> // provides xmlChar and xmlGetUTF8Char, etc.

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Limit allocation to a reasonable size to avoid OOM in the harness.
    const size_t MAX_ALLOC = 1 << 20; // 1MiB
    size_t buf_len = Size;
    if (buf_len > MAX_ALLOC) buf_len = MAX_ALLOC;

    // Ensure at least one byte so we can place a terminating NUL.
    if (buf_len == 0) buf_len = 1;

    // Provide additional padding to allow short reads (e.g. UTF-8 multi-byte
    // checks up to 4 bytes) without reading past the allocation.
    const size_t PADDING = 4;
    unsigned char *buf = (unsigned char *)malloc(buf_len + 1 + PADDING);
    if (!buf) return 0;

    // Copy available fuzz data (or pad with zeros if truncated by MAX_ALLOC)
    if (Size > 0) {
        size_t to_copy = (Size < buf_len) ? Size : buf_len;
        memcpy(buf, Data, to_copy);
        if (to_copy < buf_len)
            memset(buf + to_copy, 0, buf_len - to_copy);
    } else {
        memset(buf, 0, buf_len);
    }
    // Null-terminate to make the buffer safe for string-like scanning.
    buf[buf_len] = 0;
    // Zero the extra padding bytes as well.
    memset(buf + buf_len + 1, 0, PADDING);

    // Prepare an xmlParserInput instance. Zero-init to avoid
    // using uninitialized fields inside the function.
    xmlParserInput input;
    memset(&input, 0, sizeof(input));

    // Set base/end/cur to point into our buffer.
    input.base = (const xmlChar *)buf;
    // Keep `end` pointing to the logical end (the position of the terminator)
    // so library semantics remain correct.
    input.end = (const xmlChar *)(buf + buf_len);

    // Choose a current position inside the buffer.
    // If any data is present, derive an offset from the first byte.
    size_t cur_off = 0;
    if (Size > 0) {
        // Avoid modulo by zero (buf_len >= 1 by construction)
        cur_off = (size_t)Data[0] % buf_len;
    }
    input.cur = input.base + cur_off;

    // Prepare sizeInOut (max window size) using a small default or fuzz-derived value.
    int sizeInOut = 80; // default LINE_LEN from libxml2 internals
    if (Size >= 2) {
        // Use second byte to vary the requested window size, keep it reasonable.
        sizeInOut = 1 + (int)(Data[1] % 512);
    }

    int offsetOut = 0;
    const xmlChar *startOut = NULL;

    // Call the function under test.
    // It is expected to read from input->base..input->end and update outputs.
    xmlParserInputGetWindow(&input, &startOut, &sizeInOut, &offsetOut);

    // Use the outputs in a way that the compiler won't optimize away the call.
    if (startOut != NULL && sizeInOut > 0) {
        // Guard against reading out-of-range: ensure startOut points inside our buffer.
        if (startOut >= input.base && startOut < input.end) {
            volatile unsigned char v = (unsigned char)startOut[0];
            (void)v;
        }
    }

    // Free heap resources.
    free(buf);

    return 0;
}
