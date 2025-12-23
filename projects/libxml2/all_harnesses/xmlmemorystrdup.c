// /src/libxml2/fuzz/regexp.c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include the libxml2 memory API header (absolute project path) */
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 * Fuzzer entry point expected by libFuzzer / LLVMFuzzer.
 * This driver converts the arbitrary input bytes into a NUL-terminated
 * C string and calls xmlMemoryStrdup on it. The duplicated string is
 * then freed with xmlMemFree (part of the libxml2 memory API).
 *
 * NOTE: xmlMemoryStrdup uses strlen() on the input C string, so if the
 * input contains embedded NUL bytes many inputs will be treated as
 * identical by strlen(). To make the fuzzer see and exercise all bytes
 * we map any embedded NUL bytes to a non-zero value before NUL-terminating.
 */

/* Ensure the symbol has C linkage when compiled as C++ so libFuzzer can discover it. */
#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Guard against ridiculously large sizes that would overflow when adding 1 */
    if (Size == SIZE_MAX) {
        return 0;
    }

    /* Allocate a buffer one byte larger than Size to ensure NUL-termination. */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        return 0;
    }

    if (Size > 0 && Data != NULL) {
        /* Copy data but ensure there are no internal NULs (map to 0x01). */
        for (size_t i = 0; i < Size; ++i) {
            unsigned char c = Data[i];
            buf[i] = (c == '\0') ? '\x01' : (char)c;
        }
    }
    buf[Size] = '\0'; /* Ensure a valid C string */

    /* Call the target function under test. */
    char *dup = xmlMemoryStrdup(buf);

    /* Use the duplicated string to make sure the fuzzer data is actually consumed
     * (so coverage can change based on input). */
    if (dup != NULL) {
        /* Query the library for the size (exercises xmlMemSize). */
        size_t dsz = xmlMemSize(dup);
        (void)dsz; /* suppress unused variable warnings in some builds */

        /* Use strlen to determine the logical number of bytes to touch.
         * This ensures we actually iterate over the string bytes even if
         * xmlMemSize has a different semantics. */
        size_t len = strlen(dup);

        /* Touch each byte of the duplicated string to ensure it's read. */
        for (size_t i = 0; i < len; ++i) {
            volatile char v = dup[i];
            (void)v;
        }

        /* As an additional variation, if the string has at least 2 chars,
         * create a tiny rotated version and duplicate it too (exercises more paths). */
        if (len > 1) {
            char tmp = dup[0];
            /* create a small rotated copy on the heap to keep things safe */
            char *rot = (char *)malloc(len + 1);
            if (rot != NULL) {
                /* rotate left by one (and ensure NUL-termination) */
                for (size_t i = 0; i + 1 < len; ++i)
                    rot[i] = dup[i + 1];
                rot[len - 1] = tmp;
                rot[len] = '\0';

                /* ensure NUL-terminated (dup is NUL-terminated so rot will be too) */
                char *dup2 = xmlMemoryStrdup(rot);
                if (dup2 != NULL) {
                    /* touch bytes (and also query xmlMemSize to exercise it) */
                    size_t d2sz = xmlMemSize(dup2);
                    (void)d2sz;
                    size_t len2 = strlen(dup2);
                    for (size_t i = 0; i < len2; ++i) {
                        volatile char v2 = dup2[i];
                        (void)v2;
                    }
                    xmlMemFree(dup2);
                }
                free(rot);
            }
        }

        /* Free the duplicated memory using the library free function. */
        xmlMemFree(dup);
    }

    free(buf);

    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
