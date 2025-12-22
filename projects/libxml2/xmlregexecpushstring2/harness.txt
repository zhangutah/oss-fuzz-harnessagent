#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Use the project header found for the symbol */
#include "/src/libxml2/include/libxml/xmlregexp.h"

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Cap allocations to avoid excessive memory use in the fuzzer run. */
    const size_t MAX_COPY = 4096;
    size_t use = Size < MAX_COPY ? Size : MAX_COPY;

    /* Map the input bytes to an 'a'/'b' alphabet so the regexp "(a|b)*" is meaningfully exercised. */
    xmlChar *mapped = (xmlChar *)malloc(use + 1);
    if (mapped == NULL)
        return 0;
    for (size_t i = 0; i < use; ++i) {
        /* map to 'a' or 'b' deterministically from each byte */
        mapped[i] = (Data[i] & 1) ? (xmlChar)'a' : (xmlChar)'b';
    }
    mapped[use] = 0;

    /* Compile a simple deterministic regexp to create a valid xmlRegexp object. */
    const xmlChar *pattern = (const xmlChar *)"(a|b)*";
    xmlRegexp *comp = xmlRegexpCompile(pattern);
    if (comp == NULL) {
        free(mapped);
        return 0;
    }

    /* Create an execution context (no callbacks, no user data). */
    xmlRegExecCtxt *exec = xmlRegNewExecCtxt(comp, NULL, NULL);
    if (exec == NULL) {
        xmlRegFreeRegexp(comp);
        free(mapped);
        return 0;
    }

    /* Use the fuzz data to drive many push calls with different splits.
       Limit the number of splits to avoid too many allocations in a single run. */
    const size_t MAX_SPLITS = 64;
    size_t max_splits = use > 1 ? (use - 1) : 0;
    if (max_splits > MAX_SPLITS) max_splits = MAX_SPLITS;

    for (size_t s = 1; s <= max_splits; ++s) {
        size_t len1 = s;
        size_t len2 = use - s;

        /* Allocate NUL-terminated substrings for value and value2. */
        xmlChar *value = (xmlChar *)malloc(len1 + 1);
        xmlChar *value2 = (xmlChar *)malloc(len2 + 1);
        if (value == NULL || value2 == NULL) {
            free(value);
            free(value2);
            break;
        }
        memcpy(value, mapped, len1);
        value[len1] = 0;
        memcpy(value2, mapped + len1, len2);
        value2[len2] = 0;

        /* Call the target function with our fuzzed strings. */
        (void)xmlRegExecPushString2(exec, value, value2, NULL);

        /* Also call a variant with value2 == NULL to exercise that code path. */
        (void)xmlRegExecPushString2(exec, value, NULL, NULL);

        free(value2);
        free(value);
    }

    /* Additionally, use the whole mapped buffer as a single token (value2 == NULL). */
    (void)xmlRegExecPushString2(exec, mapped, NULL, NULL);

    /* Clean up the execution context and compiled regexp. */
    xmlRegFreeExecCtxt(exec);
    xmlRegFreeRegexp(comp);

    free(mapped);
    return 0;
}
