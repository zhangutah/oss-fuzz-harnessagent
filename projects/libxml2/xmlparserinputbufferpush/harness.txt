#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

/* Adjust these paths if your build uses different include locations. */
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzz driver for: int xmlParserInputBufferPush(xmlParserInputBuffer * in, int len, const char * buf);
 Fuzzer entry point: LLVMFuzzerTestOneInput

 Fix summary:
 - Previously the harness always created a parser input buffer with
   XML_CHAR_ENCODING_NONE and pushed the entire input in one call.
   That resulted in limited code-path coverage because xmlParserInputBufferPush
   has a different branch when the parser input buffer has a non-NULL encoder.
 - This fixed harness:
   * Uses the first byte of the fuzzer input to decide whether to create the
     parser input buffer with an encoder (e.g., XML_CHAR_ENCODING_UTF8) or
     without one (XML_CHAR_ENCODING_NONE). This exercises both branches.
   * Uses the remaining bytes as the data to push.
   * Pushes the data in multiple small chunks (chunk sizes derived from the
     fuzzer bytes) to explore more internal behaviour across multiple calls.
   * Caps chunk sizes to avoid very large allocations.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Use the first byte of the input to pick whether to request an encoder.
       This will toggle the xmlParserInputBufferPush path that converts raw
       bytes when an encoder is present. */
    uint8_t mode = Data[0];

    /* Choose encoding based on mode bit 0 */
    xmlCharEncoding enc = (mode & 1) ? XML_CHAR_ENCODING_UTF8 : XML_CHAR_ENCODING_NONE;

    /* Create the parser input buffer with the chosen encoding. */
    xmlParserInputBuffer *in = xmlAllocParserInputBuffer(enc);
    if (in == NULL) {
        return 0;
    }

    /* If there's no data beyond the mode byte, nothing to push. */
    if (Size <= 1) {
        xmlFreeParserInputBuffer(in);
        return 0;
    }

    /* The rest of the bytes are the payload to push. We'll push them in
       multiple small chunks, with sizes influenced by the bytes themselves,
       to exercise more code paths. */
    const uint8_t *payload = Data + 1;
    size_t payload_size = Size - 1;
    const size_t MAX_TOTAL_PUSH = 256 * 1024; /* safety overall cap */
    const size_t MAX_CHUNK = 8192;            /* safety per-call cap */

    size_t total_pushed = 0;
    size_t offset = 0;
    while (offset < payload_size && total_pushed < MAX_TOTAL_PUSH) {
        /* Derive a chunk size from the current byte to get varied sizes.
           Add 1 so chunk isn't zero. */
        size_t remaining = payload_size - offset;
        size_t suggested = (payload[offset] & 0x7F) + 1; /* 1..128 */
        size_t chunk = suggested;
        if (chunk > remaining) chunk = remaining;
        if (chunk > MAX_CHUNK) chunk = MAX_CHUNK;
        if (chunk > (size_t)INT_MAX) chunk = (size_t)INT_MAX;

        /* Call the function under test. */
        (void)xmlParserInputBufferPush(in, (int)chunk, (const char *)(payload + offset));

        total_pushed += chunk;
        offset += chunk;
    }

    /* Clean up */
    xmlFreeParserInputBuffer(in);
    return 0;
}
