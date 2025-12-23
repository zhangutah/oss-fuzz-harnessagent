#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h> /* for xmlNewStringInputStream */
#include <libxml/SAX2.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h> /* for xmlMalloc/xmlFree if needed */

/*
 * Fuzz driver for:
 *   void xmlSAX2ExternalSubset(void * ctx,
 *                              const xmlChar * name,
 *                              const xmlChar * publicId,
 *                              const xmlChar * systemId);
 *
 * Strategy:
 * - Split the fuzzer input into three NUL-terminated xmlChar* strings:
 *   name, publicId, systemId.
 * - Create a xmlParserCtxt using xmlNewParserCtxt().
 * - Provide a simple resolveEntity SAX callback that returns an
 *   xmlParserInput created from the systemId (or publicId) using
 *   xmlNewStringInputStream so xmlSAX2ExternalSubset can fetch an
 *   "external subset" to parse.
 * - Ensure parser context fields used by xmlSAX2ExternalSubset are set:
 *   myDoc != NULL and validate/wellFormed flags.
 * - Reuse the SAX handler already allocated by xmlNewParserCtxt so
 *   xmlFreeParserCtxt can free it safely, then call xmlSAX2ExternalSubset
 *   and free resources.
 */

static xmlParserInputPtr
fuzz_resolve_entity(void *userData, const xmlChar *publicId, const xmlChar *systemId) {
    if (userData == NULL)
        return NULL;
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr)userData;
    /* Prefer systemId as the content source; fall back to publicId, else empty */
    const xmlChar *content = systemId ? systemId : (publicId ? publicId : (const xmlChar *)"");
    /* Create an input stream from the provided content */
    return xmlNewStringInputStream(ctxt, content);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Split Data into three roughly equal parts for name, publicId, systemId */
    size_t len1 = Size / 3;
    size_t len2 = (Size - len1) / 2;
    size_t len3 = Size - len1 - len2;

    /* Allocate and copy with NUL-termination */
    unsigned char *name = (unsigned char *)malloc(len1 + 1);
    unsigned char *publicId = (unsigned char *)malloc(len2 + 1);
    unsigned char *systemId = (unsigned char *)malloc(len3 + 1);

    if (!name || !publicId || !systemId) {
        free(name); free(publicId); free(systemId);
        return 0;
    }

    memcpy(name, Data, len1);
    name[len1] = '\0';

    memcpy(publicId, Data + len1, len2);
    publicId[len2] = '\0';

    memcpy(systemId, Data + len1 + len2, len3);
    systemId[len3] = '\0';

    /* Create parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        free(name); free(publicId); free(systemId);
        return 0;
    }

    /* Set userData to the context so our resolver can access it */
    ctxt->userData = ctxt;

    /*
     * Reuse the SAX handler allocated inside xmlNewParserCtxt/xmlInitSAXParserCtxt.
     * Do NOT allocate another handler and overwrite ctxt->sax, otherwise the
     * handler allocated internally will be leaked.
     */
    if (ctxt->sax == NULL) {
        /* If for some reason it's NULL, try to allocate one so xmlFreeParserCtxt
         * will have something consistent to free. This is unlikely because
         * xmlNewParserCtxt initializes it, but handle defensively.
         */
        ctxt->sax = (xmlSAXHandler *)xmlMalloc(sizeof(xmlSAXHandler));
        if (ctxt->sax == NULL) {
            xmlFreeParserCtxt(ctxt);
            free(name); free(publicId); free(systemId);
            return 0;
        }
        memset(ctxt->sax, 0, sizeof(*ctxt->sax));
        xmlSAXVersion(ctxt->sax, 2);
        ctxt->userData = ctxt;
    }

    /* Install our entity resolver into the existing SAX handler */
    ctxt->sax->resolveEntity = fuzz_resolve_entity;

    /* Ensure conditions in xmlSAX2ExternalSubset are met */
    ctxt->validate = 1;      /* make (ctxt->validate) true */
    ctxt->wellFormed = 1;    /* ensure wellFormed is true */
    /* create a document so myDoc != NULL */
    ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
    if (ctxt->myDoc == NULL) {
        /* cleanup; xmlFreeParserCtxt will free sax handler */
        xmlFreeParserCtxt(ctxt);
        free(name); free(publicId); free(systemId);
        return 0;
    }

    /* Call the target function with our fuzzed strings */
    xmlSAX2ExternalSubset((void *)ctxt,
                         (const xmlChar *)name,
                         (const xmlChar *)publicId,
                         (const xmlChar *)systemId);

    /* Cleanup */
    if (ctxt->myDoc)
        xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt); /* this will free ctxt->sax (the handler allocated by libxml2 or above) */

    free(name);
    free(publicId);
    free(systemId);

    /* Cleanup global parser state to avoid left-over allocations reported by ASAN */
    xmlCleanupParser();

    return 0;
}
