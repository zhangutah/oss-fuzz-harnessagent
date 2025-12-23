#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Use the header that declares xmlUTF8Strsize and xmlChar.
   Prefer absolute path as returned by analysis tools. */
#include "/src/libxml2/include/libxml/xmlstring.h"

/* Helper: clamp a uint64_t to int safely */
static int clamp_to_int(uint64_t v) {
    if (v == 0) return 0;
    if (v > (uint64_t)INT_MAX) return INT_MAX;
    return (int)v;
}

/* Fuzzer entry point expected by libFuzzer/OSS-Fuzz */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* If no data, exercise the utf == NULL branch */
    if (Size == 0) {
        /* xmlUTF8Strsize should return 0 when utf == NULL */
        (void)xmlUTF8Strsize(NULL, 1);
        return 0;
    }

    /* Determine selector from first byte */
    uint8_t selector = Data[0];

    /* Compute candidate lengths */
    int len_from_size = clamp_to_int(Size);

    uint32_t v = 0;
    if (Size >= 4) {
        /* little-endian composition */
        v = ((uint32_t)Data[0]) |
            ((uint32_t)Data[1] << 8) |
            ((uint32_t)Data[2] << 16) |
            ((uint32_t)Data[3] << 24);
    } else {
        v = (uint32_t)Size;
    }
    int len_from_bytes = (int)(v & 0x7FFFFFFF);
    if (len_from_bytes == 0) len_from_bytes = 1;

    int chosen_len;
    switch (selector & 0x3) {
        case 0:
            chosen_len = len_from_size;
            break;
        case 1:
            chosen_len = len_from_bytes;
            break;
        case 2:
            chosen_len = INT_MAX;
            break;
        default:
            chosen_len = -1; /* exercise len <= 0 branch */
            break;
    }

    /* Ensure chosen_len is within int range (clamp again just in case) */
    if (chosen_len > INT_MAX) chosen_len = INT_MAX;
    if (chosen_len < INT_MIN) chosen_len = INT_MIN;

    /*
     * xmlUTF8Strsize will read bytes from the utf pointer until it either
     * reaches a NUL byte or consumes 'len' characters. The fuzzer-provided
     * Data buffer is not guaranteed to be NUL-terminated, and chosen_len may
     * be larger than Size, so calling the function directly can read past
     * the provided buffer and cause a heap-buffer-overflow. To avoid that,
     * copy the input into a local buffer and append a terminating NUL so the
     * function always stops within allocated memory.
     */

    xmlChar *buf = (xmlChar *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = 0; /* ensure termination */

    /* Call the function under test. Cast to void to ignore the return value. */
    (void)xmlUTF8Strsize((const xmlChar *)buf, chosen_len);

    free(buf);

    return 0;
}
