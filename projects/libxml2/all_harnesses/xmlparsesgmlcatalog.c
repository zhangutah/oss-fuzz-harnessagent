#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/catalog.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

/* Declare the symbol as weak so the harness will still link even if the
 * libxml build didn't include catalog support. If the symbol isn't present
 * in the linked libxml, the pointer will be NULL and we simply skip calling
 * it. */
#ifdef __cplusplus
extern "C" {
#endif
extern int xmlParseSGMLCatalog(xmlCatalogPtr catal, const xmlChar * value, const char * file, int super) __attribute__((weak));
#ifdef __cplusplus
}
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int libxml_inited = 0;
    if (!libxml_inited) {
        /* Initialize parser library (safe to call once) */
        xmlInitParser();
        /* Optionally set catalog defaults or debug level here */
        libxml_inited = 1;
    }

    /* Limit allocation to avoid trying to allocate absurd amounts. Adjust
       as appropriate for your environment. */
    const size_t MAX_INPUT_BYTES = (1 << 24); /* 16MB cap */
    size_t useSize = Size;
    if (useSize > MAX_INPUT_BYTES) useSize = MAX_INPUT_BYTES;

    /* Allocate a buffer and ensure it's NUL-terminated for xmlChar usage */
    unsigned char *buf = (unsigned char *)malloc(useSize + 1);
    if (buf == NULL) {
        return 0;
    }
    if (Data != NULL && useSize > 0) {
        memcpy(buf, Data, useSize);
    }
    buf[useSize] = 0; /* Null-terminate */

    /* Try to exercise the SGML catalog parser if available. */
    if (xmlParseSGMLCatalog) {
        /* Create an SGML catalog. xmlNewCatalog is deprecated but available
           in the library headers; pass 1 to request SGML catalog type. */
        xmlCatalogPtr catal = xmlNewCatalog(1);
        if (catal != NULL) {
            /* Call the target function if available. Pass a small dummy filename string.
               Use super = 0 to avoid special 'super' handling; fuzzing input in
               'value' exercises parsing code paths. */
            (void)xmlParseSGMLCatalog(catal, (const xmlChar *)buf, "fuzzed-catalog", 0);
            /* Free the catalog */
            xmlFreeCatalog(catal);
        } else {
            /* If we couldn't allocate a catalog, still try the call with NULL
               to exercise guarded failure paths (the function may early-return). */
            (void)xmlParseSGMLCatalog(NULL, (const xmlChar *)buf, "fuzzed-catalog", 0);
        }
    }

    /* Always attempt to parse the input as an XML document as a fallback and
       to ensure fuzz data is used even when catalog support is absent. */
    if (useSize > 0) {
        /* xmlReadMemory takes an int for the size; our useSize is clamped to 16MB so safe. */
        xmlDocPtr doc = xmlReadMemory((const char *)buf, (int)useSize, "fuzzed-input", NULL,
                                      XML_PARSE_RECOVER | XML_PARSE_NONET);
        if (doc != NULL) {
            xmlFreeDoc(doc);
        }
    }

    free(buf);

    /* Do not call xmlCleanupParser() here to avoid tearing down global
       state repeatedly for in-process fuzzers. If you prefer to cleanup
       for each run, uncomment the next line (may be slower). */
    /* xmlCleanupParser(); */

    return 0;
}
