#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/* Silence libxml error output in the fuzzer to avoid lots of stdout/stderr noise. */
static void
fuzzXmlErrorFunc(void *ctx, const char *msg, ...)
{
    /* discard errors */
    (void)ctx;
    (void)msg;
}

/* Optional initializer called by libFuzzer before fuzzing starts. */
int
LLVMFuzzerInitialize(int *argc, char ***argv) {
    /* Setup libxml fuzz-friendly environment */
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, fuzzXmlErrorFunc);
    return 0;
}

/* The fuzzer entry */
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Avoid very large inputs to limit resource use */
    if (Size == 0 || Size > 200000)
        return 0;

    /* We will split the input into two parts:
       - name (must be non-NULL and non-empty to exercise xmlNewDocProp)
       - value (can be empty)
       The split is chosen deterministically from the input. */

    size_t split;
    if (Size == 1) {
        split = 1;
    } else {
        /* Choose split in [1, Size-1] using first byte to introduce variety */
        split = 1 + (Data[0] % (Size - 1));
    }

    size_t name_len = split;
    size_t value_len = (Size > split) ? (Size - split) : 0;

    /* Allocate buffers and ensure NUL termination. Using unsigned char for xmlChar. */
    unsigned char *name = (unsigned char *)malloc(name_len + 1);
    unsigned char *value = (unsigned char *)malloc(value_len + 1);
    if (name == NULL || value == NULL) {
        free(name);
        free(value);
        return 0;
    }

    memcpy(name, Data, name_len);
    name[name_len] = '\0';
    if (value_len)
        memcpy(value, Data + split, value_len);
    value[value_len] = '\0';

    /* Optionally create an xmlDoc. Passing NULL is also valid for xmlNewDocProp.
       Use a simple policy: create a doc if the low bit of the first byte is set (when available). */
    xmlDocPtr doc = NULL;
    if (Size >= 1 && (Data[0] & 1)) {
        doc = xmlNewDoc((const xmlChar *)"1.0");
        /* It's fine if xmlNewDoc returns NULL on failure; xmlNewDocProp handles doc == NULL */
    }

    /* Call the function under test. Cast C buffers to xmlChar *. */
    xmlAttrPtr attr = xmlNewDocProp(doc, (const xmlChar *)name, (const xmlChar *)value);

    /* If an attribute was created, free it properly. */
    if (attr != NULL) {
        xmlFreeProp(attr);
    }

    /* Clean up document if we created one. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Reset libxml error state to avoid leaking error objects between runs. */
    xmlResetLastError();

    free(name);
    free(value);

    return 0;
}
