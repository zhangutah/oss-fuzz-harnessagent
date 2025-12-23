#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

#include <libxml/parserInternals.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Fuzz driver for:
 *     void xmlParseComment(xmlParserCtxt * ctxt);
 *
 * This driver:
 *  - Initializes the libxml parser once.
 *  - Creates a parser context for each fuzz input.
 *  - Pushes the fuzz data as a parsing chunk into the context using
 *    xmlCtxtResetPush so the parser input pointers are set up.
 *  - Ensures ctxt->myDoc is a valid xmlDoc so handlers that create nodes
 *    (e.g. xmlSAX2Comment -> xmlNewDocComment -> xmlSAX2AppendChild)
 *    have a valid parent to attach to and don't dereference NULL.
 *  - Calls xmlParseComment(ctxt).
 *  - Frees the created xmlDoc and the parser context.
 *
 * Note: xmlCtxtResetPush takes an int for size, so large inputs are truncated
 * to INT_MAX.
 */

extern void xmlInitParser(void);
extern xmlParserCtxt *xmlNewParserCtxt(void);
extern void xmlFreeParserCtxt(xmlParserCtxt *ctxt);
extern int xmlCtxtResetPush(xmlParserCtxt *ctxt,
                            const char *chunk, int size,
                            const char *filename, const char *encoding);
extern void xmlParseComment(xmlParserCtxt *ctxt);
extern xmlDocPtr xmlNewDoc(const xmlChar *version);
extern void xmlFreeDoc(xmlDocPtr cur);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* xmlCtxtResetPush expects an int size */
    int sz = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    xmlParserCtxt *ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Push the fuzz data into the context as the current parsing chunk.
     * filename and encoding can be NULL; provide a short filename for diagnostics.
     *
     * xmlCtxtResetPush will call xmlCtxtReset(ctxt) which clears ctxt fields,
     * so we must set ctxt->myDoc after the push to ensure handlers that create
     * nodes have a valid document to attach to.
     */
    if (xmlCtxtResetPush(ctxt, (const char *)Data, sz, "fuzz-input", NULL) == 0) {
        /* Ensure there's a document to attach nodes to. xmlSAX2Comment and
         * related handlers expect ctxt->myDoc to be non-NULL. */
        xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
        if (doc != NULL) {
            ctxt->myDoc = doc;
            /* Attempt to parse a comment at the current input position.
             * xmlParseComment will return quickly if the data does not start with "<!".
             */
            xmlParseComment(ctxt);

            /* Free the document created above. xmlFreeParserCtxt does NOT
             * free ctxt->myDoc, so free it here to avoid leaks across runs.
             */
            xmlFreeDoc(doc);
            ctxt->myDoc = NULL;
        } else {
            /* If we couldn't allocate a doc, still attempt parsing but avoid
             * leaving ctxt->myDoc as a dangling pointer. */
            xmlParseComment(ctxt);
        }
    }

    xmlFreeParserCtxt(ctxt);
    return 0;
}
