#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Include the libxml2 header discovered in the project workspace.
   If building outside the project you may replace this with <libxml/tree.h>
   or the appropriate include path for your libxml2 installation. */
#include "/src/libxml2/include/libxml/tree.h"

#ifndef INT_MAX
#include <limits.h>
#endif

// Fuzzer entry point expected by libFuzzer/LLVMFuzzer.
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Defensive checks
    if (Data == NULL) return 0;
    if (Size == 0) return 0;

    // Limit allocations to a reasonable max to avoid OOM on very large inputs.
    // You can increase this if desired, but keep it reasonable for fuzz runs.
    const size_t MAX_ALLOC = 1 << 20; // 1MB

    // Clamp the length to a safe maximum that's also within int range.
    size_t use_size = Size;
    if (use_size > MAX_ALLOC) use_size = MAX_ALLOC;
    if (use_size > (size_t)INT_MAX - 1) use_size = (size_t)INT_MAX - 1;

    int len = (int)use_size;

    // Create a temporary NUL-terminated copy of the fuzzer data so string-based
    // code paths (e.g., xmlStrlen) operate within bounds and actually see the bytes.
    uint8_t *tmp = (uint8_t *)malloc((size_t)len + 1);
    if (tmp == NULL) return 0;
    memcpy(tmp, Data, (size_t)len);
    tmp[len] = 0; // NUL-terminate the copy

    // Create a buffer sized to accommodate the input plus a terminating NUL,
    // which can reduce the number of internal growth operations.
    xmlBuffer *buf = xmlBufferCreateSize((size_t)len + 1);
    if (buf == NULL) {
        free(tmp);
        return 0;
    }

    // xmlBufferAdd expects const xmlChar* (xmlChar is unsigned char).
    // Pass -1 to let xmlBufferAdd call xmlStrlen on our NUL-terminated tmp,
    // which makes the function actually inspect the fuzz bytes to compute length.
    (void)xmlBufferAdd(buf, (const xmlChar *)tmp, -1);

    // Clean up
    xmlBufferFree(buf);
    free(tmp);

    return 0;
}

// Optional local test harness: read a file into memory and call the fuzzer entry.
// Build/run this file as a standalone program to exercise the same path.
#ifdef FUZZER_STANDALONE_MAIN
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    const char *filename = argv[1];
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        perror("ftell");
        fclose(f);
        return 1;
    }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        perror("fread");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    LLVMFuzzerTestOneInput(buf, (size_t)sz);

    free(buf);
    return 0;
}
#endif  // FUZZER_STANDALONE_MAIN
