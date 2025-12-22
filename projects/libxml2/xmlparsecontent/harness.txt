#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include <libxml/parserInternals.h> /* contains xmlParseContent, xmlCreateMemoryParserCtxt */
#include <libxml/parser.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlmemory.h>
#include <libxml/tree.h>

static void libxml2_init_once(void) {
    static int initialized = 0;
    if (initialized) return;
    /* initialize the library (thread-safe init is fine here) */
    xmlInitParser();
    /* disable libxml2 generic error output to stderr to avoid spamming fuzzer logs */
    xmlSetGenericErrorFunc(NULL, NULL);
    initialized = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Ensure libxml2 is initialized once */
    libxml2_init_once();

    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* xmlCreateMemoryParserCtxt takes an (const char *) and an int size.
       Clamp size to INT_MAX to avoid overflow when converting. */
    int int_size = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a parser context that parses from the provided memory buffer. */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt((const char *)Data, int_size);
    if (ctxt == NULL) {
        return 0;
    }

    /* Ensure there is a valid document/node parent for content parsing.
       xmlParseContent (and SAX2 append helpers) expect ctxt->myDoc or ctxt->node
       to be non-NULL so appended nodes have a parent. */
    if (ctxt->myDoc == NULL) {
        /* Create a minimal document; xmlNewDoc returns an xmlDocPtr.
           BAD_CAST is a common libxml2 macro for casting string literals. */
        xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc != NULL) {
            ctxt->myDoc = doc;
            /* set ctxt->node to the document so xmlSAX2AppendChild will use it */
            ctxt->node = (xmlNodePtr)ctxt->myDoc;
        }
    }

    /* Call the target function under test. */
    xmlParseContent(ctxt);

    /* Clean up the created document if any (follow pattern from xmlSAXUserParseMemory) */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Clean up the parser context. */
    xmlFreeParserCtxt(ctxt);

    /* Note: we intentionally do not call xmlCleanupParser() here because the
       fuzzer will call this function many times. xmlCleanupParser() should
       only be called at process shutdown if desired. */

    return 0;
}
