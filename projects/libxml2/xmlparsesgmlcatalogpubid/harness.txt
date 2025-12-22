// Fuzz driver that uses the real xmlParseSGMLCatalogPubid implementation
// from the libxml2 project (include the source so the static symbol is
// available in this translation unit).
//
// Do not change the signature of LLVMFuzzerTestOneInput.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * Ensure the SGML catalog parsing code is compiled in when we include
 * the source file. The catalog.c code is guarded by these macros.
 */
#ifndef LIBXML_CATALOG_ENABLED
#define LIBXML_CATALOG_ENABLED
#endif

#ifndef LIBXML_SGML_CATALOG_ENABLED
#define LIBXML_SGML_CATALOG_ENABLED
#endif

/* Include the project's catalog.c so we use the real function (static). */
#include "../catalog.c"

/*
 * libFuzzer entry point.
 *
 * This copies the input into a null-terminated buffer and calls the real
 * xmlParseSGMLCatalogPubid from catalog.c. Any buffer allocated by the
 * parser and returned in `id` is freed using xmlFree (project memory API).
 */
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* make a null-terminated copy of Data */
    xmlChar *buf = (xmlChar *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    if (Size > 0)
        memcpy(buf, Data, Size);
    buf[Size] = 0;

    xmlChar *id = NULL;
    /* call the real function from catalog.c */
    (void)xmlParseSGMLCatalogPubid((const xmlChar *)buf, &id);

    /* free any memory returned in id */
    if (id != NULL) {
        /* xmlFree is provided by libxml2; catalog.c expects it */
        xmlFree(id);
    }

    free(buf);
    return 0;
}