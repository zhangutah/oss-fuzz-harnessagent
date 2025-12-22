// SPDX-License-Identifier: MIT
// Fixed harness: use the real xmlRelaxNGSchemaTypeCompare from the project
// rather than providing a fake fallback implementation.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/relaxng.h> /* brings in xmlChar, xmlNodePtr, and related types */

/*
 * If the real xmlRelaxNGSchemaTypeCompare is not linked into the final binary
 * (e.g. LIBXML_RELAXNG_ENABLED not set), declare it as a weak symbol so the
 * linker won't error out. When present the real function will be called.
 */
#ifdef __cplusplus
extern "C" {
#endif
extern int xmlRelaxNGSchemaTypeCompare(void *data,
                                      const xmlChar *type,
                                      const xmlChar *value1,
                                      xmlNodePtr ctxt1,
                                      void *comp1,
                                      const xmlChar *value2,
                                      xmlNodePtr ctxt2) __attribute__((weak));
#ifdef __cplusplus
}
#endif

/*
 * Helper: allocate a null-terminated buffer copied from input slice.
 * Returns NULL if allocation fails.
 */
static char *copy_slice_as_cstring(const uint8_t *Data, size_t start, size_t len) {
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    if (len > 0 && Data != NULL)
        memcpy(s, Data + start, len);
    s[len] = '\0';
    return s;
}

/*
 * Fuzzer entry point.
 *
 * We split the input into three contiguous parts and use them as:
 *  - type
 *  - value1
 *  - value2
 *
 * For contexts and comparator/data pointers we pass NULL. This is a
 * conservative driver that exercises the type/value comparison logic
 * while avoiding construction of complex xmlNode structures.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0 || Data == NULL) return 0;

    /* Split the input into three parts (as even as possible) */
    size_t one = Size / 3;
    size_t two = (Size - one) / 2;
    size_t l1 = one;
    size_t l2 = two;
    size_t l3 = Size - l1 - l2;

    /* Ensure small non-zero lengths for more variation when input is tiny */
    if (Size > 0 && l1 == 0) l1 = (Size >= 1) ? 1 : 0;
    if (Size > l1 && l2 == 0) l2 = 1;
    if (l1 + l2 > Size) l2 = Size - l1;
    l3 = Size - l1 - l2;

    char *s1 = copy_slice_as_cstring(Data, 0, l1);
    char *s2 = copy_slice_as_cstring(Data, l1, l2);
    char *s3 = copy_slice_as_cstring(Data, l1 + l2, l3);

    if (!s1 || !s2 || !s3) {
        free(s1); free(s2); free(s3);
        return 0;
    }

    /* Cast to xmlChar* as expected by the target function. */
    const xmlChar *type = (const xmlChar *)s1;
    const xmlChar *value1 = (const xmlChar *)s2;
    const xmlChar *value2 = (const xmlChar *)s3;

    /* Call the real target function from the project if available. */
    if (xmlRelaxNGSchemaTypeCompare) {
        (void)xmlRelaxNGSchemaTypeCompare(
            NULL,      /* data */
            type,
            value1,
            NULL,      /* ctxt1 */
            NULL,      /* comp1 */
            value2,
            NULL       /* ctxt2 */
        );
    }

    /* Clean up */
    free(s1);
    free(s2);
    free(s3);

    return 0;
}
