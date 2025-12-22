#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Use public libxml2 headers for xmlChar and xmlFree */
#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration for the internal function we want to fuzz.
 * We avoid including the private header that exposes XML_HIDDEN and
 * other internal macros/types which cause compilation errors.
 *
 * Signature taken from the private header:
 *   const xmlChar * xmlSplitQName4(const xmlChar * name, xmlChar ** prefixPtr);
 */
const xmlChar *xmlSplitQName4(const xmlChar *name, xmlChar **prefixPtr);

#ifdef __cplusplus
}
#endif

/*
 * Fuzz target for:
 *   const xmlChar * xmlSplitQName4(const xmlChar * name, xmlChar ** prefixPtr);
 *
 * This harness turns the fuzzer input into a null-terminated xmlChar buffer,
 * calls xmlSplitQName4, frees any allocated prefix, and releases resources.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Allocate a buffer for the input plus a terminating NUL */
    xmlChar *buf = (xmlChar *)malloc(Size + 1);
    if (buf == NULL)
        return 0;

    /* Copy input bytes and NUL-terminate to form a C string */
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Call the target function */
    xmlChar *prefix = NULL;
    (void)xmlSplitQName4((const xmlChar *)buf, &prefix);

    /* xmlSplitQName4 may allocate prefix with xmlStrndup; free it if set */
    if (prefix != NULL)
        xmlFree(prefix);

    free(buf);
    return 0;
}

/* Optional standalone runner for testing outside libFuzzer */
#ifdef STANDALONE_FUZZER
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <testcase>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long size = ftell(f);
    if (size < 0) { fclose(f); return 1; }
    rewind(f);

    uint8_t *data = (uint8_t *)malloc((size_t)size);
    if (!data) { fclose(f); return 1; }

    if (fread(data, 1, (size_t)size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    LLVMFuzzerTestOneInput(data, (size_t)size);

    free(data);
    return 0;
}
#endif /* STANDALONE_FUZZER */