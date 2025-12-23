// Fuzz driver for:
//     xmlChar * xmlTextReaderLocatorBaseURI(xmlTextReaderLocatorPtr locator);
// Fuzzer entry point:
//     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// Fix: use xmlCreatePushParserCtxt so xmlParseChunk can safely operate and free the doc created by the parser

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlreader.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h> /* for xmlFree if needed */

/* Initialize libxml2 once at process start. */
__attribute__((constructor)) static void libxml_fuzz_init(void) {
    xmlInitParser();
}

/* Cleanup libxml2 at process exit. */
__attribute__((destructor)) static void libxml_fuzz_shutdown(void) {
    xmlCleanupParser();
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Cap the size fed to the parser to avoid excessive memory use. */
    const size_t MAX_FEED = 1024 * 1024; /* 1MB */
    int feed_len = (int)((Size > MAX_FEED) ? MAX_FEED : Size);

    /*
     * xmlCreatePushParserCtxt takes an initial chunk and sets up a push-mode
     * parser context. Copy the data to a temporary, NUL-terminated buffer,
     * keep it alive until after we free the parser context, then call
     * xmlParseChunk to terminate the parse so inputs are set up before calling
     * the target function.
     */
    char *buf = (char *)malloc((size_t)feed_len + 1);
    if (!buf)
        return 0;
    memcpy(buf, Data, (size_t)feed_len);
    buf[feed_len] = '\0';

    /* Create a push parser context with the initial chunk. */
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, feed_len, NULL);
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /* Signal EOF/terminate the parse. Ignore parse errors; we just want the context set up. */
    xmlParseChunk(ctxt, NULL, 0, 1);

    /* Now it's safer to call the target function: */
    xmlChar *base_uri = NULL;
    /* The implementation treats the locator as an xmlParserCtxtPtr. */
    base_uri = xmlTextReaderLocatorBaseURI((xmlTextReaderLocatorPtr)ctxt);

    if (base_uri != NULL) {
        xmlFree(base_uri);
    }

    /* Free the parser-created document if present to avoid leaking it. */
    /* xmlFreeParserCtxt() will also attempt to free the doc; clear it after freeing to avoid double-free. */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Free the parser context before freeing the buffer it may reference. */
    xmlFreeParserCtxt(ctxt);

    /* Free the copied buffer. */
    free(buf);

    return 0;
}
