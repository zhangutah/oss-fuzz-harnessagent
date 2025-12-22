#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>

/* Initialize libxml once per process. Use constructor/destructor so the fuzzer
   doesn't need to call initialization on every corpus input. */
static void libxml_init(void) __attribute__((constructor));
static void libxml_fini(void) __attribute__((destructor));

static void libxml_init(void) {
    /* xmlInitParser is safe to call multiple times; call it once at process start. */
    xmlInitParser();
}

static void libxml_fini(void) {
    /* Cleanup global parser state on process exit. */
    xmlCleanupParser();
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* xmlCreateMemoryParserCtxt takes an int for size. Clamp to INT_MAX to avoid truncation issues. */
    int sz = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a parser context from the memory buffer. */
    xmlParserCtxt *ctxt = xmlCreateMemoryParserCtxt((const char *)Data, sz);
    if (ctxt == NULL)
        return 0;

    /*
     * xmlCreateMemoryParserCtxt only creates the context. To exercise parsing
     * code paths and get coverage, run the parser on the created context.
     */
    xmlParseDocument(ctxt);

    /* If a document was created, free it to avoid memory leaks between fuzz iterations. */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Free the parser context. */
    xmlFreeParserCtxt(ctxt);

    return 0;
}
