#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the libxml2 header that declares xmlStrPrintf.
   Adjust the path if your build environment expects a different include. */
#include "/src/libxml2/include/libxml/xmlstring.h"

/* Fuzzer entry point expected by LLVM libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic sanity: nothing to do with empty input */
    if (Data == NULL || Size == 0)
        return 0;

    /* Extract an integer from the beginning of the input to use as `len`.
       We read up to 4 bytes (little-endian) when available. */
    uint32_t len_raw = 0;
    if (Size >= 4) {
        memcpy(&len_raw, Data, 4);
    } else {
        /* If fewer than 4 bytes, build the integer from what's available. */
        for (size_t i = 0; i < Size && i < 4; ++i) {
            len_raw |= ((uint32_t)Data[i]) << (8 * i);
        }
    }

    /* Clamp `len` to a reasonable maximum to avoid uncontrollable OOB writes
       while still allowing varied lengths. Allow 0..4096, but ensure we never
       pass 0 to xmlStrPrintf (it writes buf[len-1]). */
    const int MAX_LEN = 4096;
    int len = (int)(len_raw % (MAX_LEN + 1)); /* range 0..MAX_LEN */

    /* Ensure we use a safe length for the call: xmlStrPrintf expects len >= 1.
       Use safe_len for allocation and for the call; keep `len` value for variety
       if needed, but do not pass 0 to xmlStrPrintf. */
    int safe_len = (len > 0) ? len : 1;

    /* The rest of the input is used as the format string `msg`. */
    size_t msg_size = (Size > 4) ? (Size - 4) : 0;
    char *msg = (char *)malloc(msg_size + 1);
    if (msg == NULL) {
        return 0;
    }
    if (msg_size > 0) {
        memcpy(msg, Data + 4, msg_size);
    }
    msg[msg_size] = '\0'; /* ensure null-terminated */

    /* Allocate a buffer for the result using safe_len (at least 1). */
    size_t alloc_size = (size_t)safe_len;
    xmlChar *buf = (xmlChar *)malloc(alloc_size);
    if (buf == NULL) {
        free(msg);
        return 0;
    }
    /* Initialize buffer to something deterministic. */
    memset(buf, 0, alloc_size);

    /* Call the target function under test with safe_len to avoid len==0.

       Important: xmlStrPrintf is variadic and treats its third parameter
       as a format string. Passing uncontrolled fuzzer input directly as
       the format leads to undefined behavior (and crashes) if the input
       contains format specifiers. To avoid that, pass a safe format that
       prints the input as plain data. */
    (void)xmlStrPrintf(buf, safe_len, "%s", msg);

    /* Cleanup */
    free(buf);
    free(msg);

    return 0;
}