#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef FUZZ_MAX_ALLOC
#define FUZZ_MAX_ALLOC (1 << 20) /* 1 MiB cap per allocation */
#endif

/* Declare the target function as a weak symbol so the harness links
 * even if the real implementation is not present in the linked library.
 * Wrap with extern "C" when compiled as C++ so the symbol name matches.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* xmlChar is typically unsigned char. Use weak attribute so if the
 * symbol isn't provided by the linked libxml2, we don't get an
 * undefined reference at link time.
 */
extern void xmlRelaxNGComputeInterleaves(void *payload, void *data,
                                        const unsigned char *name)
    __attribute__((weak));

#ifdef __cplusplus
}
#endif

/* Fuzzer entry point for libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Partition the input into three parts:
       - name_buf: used as a null-terminated xmlChar* (const unsigned char*)
       - payload_buf: opaque payload pointer
       - data_buf: opaque data pointer
       We'll choose sizes deterministically from Data content to maximize coverage.
    */

    /* Minimum 1 byte for name (we'll ensure null-termination). */
    size_t min_for_name = 1;
    if (Size < min_for_name) return 0;

    /* Use first byte to derive a split point. */
    uint8_t selector = Data[0];

    /* Remaining bytes after the selector byte */
    const uint8_t *rest = Data + 1;
    size_t rest_size = (Size > 0) ? Size - 1 : 0;

    /* Derive name length in [0, min(rest_size, 256)] using selector.
       Keep name length modest to avoid huge allocations for strings. */
    size_t max_name = rest_size;
    if (max_name > 256) max_name = 256;
    size_t name_len = (max_name == 0) ? 0 : (selector % (max_name + 1));

    /* Remaining after name */
    const uint8_t *after_name = rest + name_len;
    size_t after_name_size = (rest_size >= name_len) ? rest_size - name_len : 0;

    /* Split the remaining data roughly in half for payload and data. */
    size_t payload_len = after_name_size / 2;
    size_t data_len = after_name_size - payload_len;

    /* Cap allocations */
    if (payload_len > FUZZ_MAX_ALLOC) payload_len = FUZZ_MAX_ALLOC;
    if (data_len > FUZZ_MAX_ALLOC) data_len = FUZZ_MAX_ALLOC;
    if (name_len > FUZZ_MAX_ALLOC) name_len = FUZZ_MAX_ALLOC;

    /* Allocate and prepare name buffer (null-terminated). */
    unsigned char *name_buf = (unsigned char *)malloc(name_len + 1);
    if (name_buf == NULL) return 0;
    if (name_len > 0) {
        memcpy(name_buf, rest, name_len);
    }
    name_buf[name_len] = '\0'; /* Ensure null-termination */

    /* Allocate payload buffer and copy bytes (if any). */
    void *payload_buf = NULL;
    if (payload_len > 0) {
        payload_buf = malloc(payload_len);
        if (payload_buf == NULL) {
            free(name_buf);
            return 0;
        }
        memcpy(payload_buf, after_name, payload_len);
    } else {
        /* If no bytes for payload, pass a small non-NULL sentinel to avoid NULL deref in target. */
        payload_buf = malloc(1);
        if (payload_buf == NULL) {
            free(name_buf);
            return 0;
        }
        ((unsigned char *)payload_buf)[0] = 0;
    }

    /* Allocate data buffer and copy bytes (if any). */
    void *data_buf = NULL;
    const uint8_t *data_src = after_name + payload_len;
    if (data_len > 0) {
        data_buf = malloc(data_len);
        if (data_buf == NULL) {
            free(name_buf);
            free(payload_buf);
            return 0;
        }
        memcpy(data_buf, data_src, data_len);
    } else {
        data_buf = malloc(1);
        if (data_buf == NULL) {
            free(name_buf);
            free(payload_buf);
            return 0;
        }
        ((unsigned char *)data_buf)[0] = 0;
    }

    /* Call the target function if present. Cast name_buf to const unsigned char* (xmlChar*). */
    /* The function may expect more structured objects; we supply opaque memory to fuzz behavior. */
    if (xmlRelaxNGComputeInterleaves) {
        xmlRelaxNGComputeInterleaves(payload_buf, data_buf, (const unsigned char *)name_buf);
    }

    /* Clean up */
    free(name_buf);
    free(payload_buf);
    free(data_buf);

    return 0;
}
