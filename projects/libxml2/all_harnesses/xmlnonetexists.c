#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* private/io.h uses XML_HIDDEN; ensure it's defined so the header compiles */
#ifndef XML_HIDDEN
#define XML_HIDDEN
#endif

/* Include the declaration for xmlNoNetExists.
   Prefer the absolute project-private header as returned by the symbol lookup tool. */
#include "/src/libxml2/include/private/io.h"

/* Fuzzer entry point expected by libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* If fuzzer provided no data, exercise the NULL filename branch. */
    if (Size == 0) {
        (void)xmlNoNetExists(NULL);
        return 0;
    }

    /* Cap the allocation size to avoid excessive memory usage in the harness. */
    const size_t MAX_LEN = 1 << 20; /* 1 MiB */
    size_t len = Size;
    if (len > MAX_LEN) len = MAX_LEN;

    char *filename = (char *)malloc(len + 1);
    if (filename == NULL) return 0;

    memcpy(filename, Data, len);
    filename[len] = '\0'; /* ensure null-terminated string */

    /* Call the target function under test. */
    (void)xmlNoNetExists(filename);

    free(filename);
    return 0;
}
