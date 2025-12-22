#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the catalog API header (project absolute path as returned). */
#include "/src/libxml2/include/libxml/catalog.h"
/* Include parser header to get xmlCleanupParser declaration. */
#include "/src/libxml2/include/libxml/parser.h"

/*
 * Fuzzer entry point.
 *
 * This harness splits the fuzzer input into three parts and passes them
 * as the 'type', 'orig' and 'replace' parameters to xmlCatalogAdd.
 *
 * If a part has length 0, a NULL pointer is passed for that parameter to
 * exercise code paths handling NULL inputs as well as empty strings.
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive limits to avoid excessive allocations from malformed inputs. */
    const size_t MAX_ALLOC = 4 * 1024 * 1024; /* 4 MB per buffer cap */
    if (Size > 3 * MAX_ALLOC) {
        /* Reduce Size used for splitting to avoid huge allocations while still fuzzing content. */
        Size = 3 * MAX_ALLOC;
    }

    /* Quick exit for empty input */
    if (Data == NULL || Size == 0)
        return 0;

    /* Split Size into three parts: len1, len2, len3 */
    size_t len1 = Size / 3;
    size_t len2 = (Size - len1) / 2;
    size_t len3 = Size - len1 - len2;

    /* Pointers for the three parameters. If a part has length 0, leave as NULL. */
    xmlChar *type_buf = NULL;
    xmlChar *orig_buf = NULL;
    xmlChar *replace_buf = NULL;

    size_t offset = 0;
    if (len1 > 0) {
        type_buf = (xmlChar *)malloc(len1 + 1);
        if (type_buf == NULL) goto cleanup;
        memcpy(type_buf, Data + offset, len1);
        type_buf[len1] = '\0';
        offset += len1;
    }

    if (len2 > 0) {
        orig_buf = (xmlChar *)malloc(len2 + 1);
        if (orig_buf == NULL) goto cleanup;
        memcpy(orig_buf, Data + offset, len2);
        orig_buf[len2] = '\0';
        offset += len2;
    }

    if (len3 > 0) {
        replace_buf = (xmlChar *)malloc(len3 + 1);
        if (replace_buf == NULL) goto cleanup;
        memcpy(replace_buf, Data + offset, len3);
        replace_buf[len3] = '\0';
        offset += len3;
    }

    /* Call the target function. It returns int; ignore the result. */
    (void)xmlCatalogAdd((const xmlChar *)type_buf,
                        (const xmlChar *)orig_buf,
                        (const xmlChar *)replace_buf);

    /*
     * Attempt to remove any added entries based on the provided values to reduce
     * lingering catalog entries between fuzzing iterations.
     * Then call xmlCleanupParser to free global parser/library state.
     *
     * xmlCleanupParser is safe here to call between fuzz runs to release global
     * allocations performed by xmlInitParser/xmlCatalogAdd.
     */
    if (orig_buf != NULL) {
        (void)xmlCatalogRemove((const xmlChar *)orig_buf);
    }
    if (replace_buf != NULL) {
        (void)xmlCatalogRemove((const xmlChar *)replace_buf);
    }

    /* Clean up global parser state to avoid leaks reported by LeakSanitizer. */
    xmlCleanupParser();

cleanup:
    if (type_buf) free(type_buf);
    if (orig_buf) free(orig_buf);
    if (replace_buf) free(replace_buf);

    return 0;
}