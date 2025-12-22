// Fixed fuzz driver for xmlSAX2ResolveEntity
// Ensures memory passed to xmlFreeParserCtxt is heap-allocated (avoid freeing string literal)

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Project header for the symbol */
#include "/src/libxml2/include/libxml/SAX2.h"
#include "/src/libxml2/include/libxml/parser.h"

/*
 Fuzzer entry point
 extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Split the input into two parts: publicId and systemId */
    size_t mid = Size / 2;
    size_t n1 = mid;
    size_t n2 = Size - mid;

    xmlChar *publicId = NULL;
    xmlChar *systemId = NULL;
    xmlParserCtxtPtr ctxt = NULL;
    xmlParserInputPtr ret = NULL;

    if (n1 > 0) {
        publicId = (xmlChar *)malloc(n1 + 1);
        if (publicId == NULL) goto cleanup;
        memcpy(publicId, Data, n1);
        publicId[n1] = '\0';
    }

    if (n2 > 0) {
        systemId = (xmlChar *)malloc(n2 + 1);
        if (systemId == NULL) goto cleanup;
        memcpy(systemId, Data + mid, n2);
        systemId[n2] = '\0';
    }

    /*
     * Create a minimal parser context. xmlSAX2ResolveEntity expects a valid
     * xmlParserCtxtPtr where either ctxt->input->filename or ctxt->directory
     * provides a base URI. To avoid NULL-base dereferences inside the function,
     * set ctxt->directory to a small heap-allocated string so xmlFreeParserCtxt
     * can safely free it.
     */
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) goto cleanup;

    /* Duplicate a small string onto the heap; xmlFreeParserCtxt will free it. */
    char *dirdup = strdup(".");
    if (dirdup == NULL) {
        /* strdup failed; free context and bail out */
        xmlFreeParserCtxt(ctxt);
        ctxt = NULL;
        goto cleanup;
    }
    /* If ctxt already had a directory, free it first to avoid leak.
       But xmlNewParserCtxt typically initializes directory to NULL. */
    if (ctxt->directory != NULL) {
        free(ctxt->directory);
    }
    ctxt->directory = dirdup;

    /* Call the target function with our constructed inputs */
    ret = xmlSAX2ResolveEntity((void *)ctxt,
                               (const xmlChar *)publicId,
                               (const xmlChar *)systemId);

    /* If a parser input was returned, free it to avoid leaks during fuzzing */
    if (ret != NULL) {
        xmlFreeInputStream(ret);
        ret = NULL;
    }

    /* Free parser context (this will free ctxt->directory which we allocated with strdup) */
    xmlFreeParserCtxt(ctxt);
    ctxt = NULL;

cleanup:
    if (publicId) free(publicId);
    if (systemId) free(systemId);

    /* It's fine to call xmlCleanupParser() in some harnesses, but avoid here
       to not affect external test harness expectations. */

    return 0;
}
