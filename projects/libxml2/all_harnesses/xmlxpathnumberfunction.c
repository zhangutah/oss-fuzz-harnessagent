#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Use absolute project headers (as located in the project workspace) */
#include "/src/libxml2/include/libxml/xpathInternals.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Fuzzer for:
 *   void xmlXPathNumberFunction(xmlXPathParserContext * ctxt, int nargs);
 *
 * Strategy:
 * - Initialize libxml2 parser state.
 * - Build a small xmlDoc and xmlNode whose content is derived from the fuzzer input.
 * - Build a xmlXPathContext (evaluation context) and a minimal xmlXPathParserContext.
 * - Based on the first input byte choose nargs = 0 or 1.
 *   - If nargs == 0: set ctxt->node to our node so the function will parse node content.
 *   - If nargs == 1: push a wrapped C string (from input) as an XPath object onto the parser
 *     value stack to exercise the casting path in xmlXPathNumberFunction.
 * - Call xmlXPathNumberFunction and then clean up all allocated resources.
 *
 * Notes:
 * - We allocate a minimal value stack (valueTab) for the parser context to allow
 *   xmlXPathValuePush/xmlXPathValuePop to operate.
 * - xmlXPathWrapCString takes ownership of the C string passed to it, so we do not free
 *   that string after wrapping; we ensure xmlXPathFreeObject is called to free it.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser subsystem and XPath internals */
    xmlInitParser();
    xmlXPathInit();

    /* Make a nul-terminated copy of the input for use as node content / string object */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Create a small XML document and a node whose content is the input data */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL) {
        free(buf);
        return 0;
    }
    xmlNodePtr node = xmlNewNode(NULL, (const xmlChar *)"root");
    if (node == NULL) {
        xmlFreeDoc(doc);
        free(buf);
        return 0;
    }
    /* Set node content from input bytes */
    xmlNodeSetContent(node, (const xmlChar *)buf);
    xmlDocSetRootElement(doc, node);

    /* Create XPath context for the document */
    xmlXPathContextPtr xpath_ctxt = xmlXPathNewContext(doc);
    if (xpath_ctxt == NULL) {
        xmlFreeDoc(doc);
        free(buf);
        return 0;
    }

    /* Allocate and initialize a minimal parser context */
    xmlXPathParserContextPtr pctxt = (xmlXPathParserContextPtr)calloc(1, sizeof(xmlXPathParserContext));
    if (pctxt == NULL) {
        xmlXPathFreeContext(xpath_ctxt);
        xmlFreeDoc(doc);
        free(buf);
        return 0;
    }
    pctxt->context = xpath_ctxt;

    /* Prepare a small value stack for the parser context */
    const int INITIAL_VALUE_MAX = 16;
    pctxt->valueMax = INITIAL_VALUE_MAX;
    pctxt->valueNr = 0;
    pctxt->valueTab = (xmlXPathObjectPtr *)calloc(pctxt->valueMax, sizeof(xmlXPathObjectPtr));
    if (pctxt->valueTab == NULL) {
        free(pctxt);
        xmlXPathFreeContext(xpath_ctxt);
        xmlFreeDoc(doc);
        free(buf);
        return 0;
    }

    /* Decide nargs based on first byte: 0 if LSB==0 else 1 */
    int nargs = (Data[0] & 1) ? 1 : 0;

    if (nargs == 0) {
        /* Set the context node so xmlXPathNumberFunction will evaluate node content */
        xpath_ctxt->node = node;
    } else {
        /* nargs == 1: create a string XPath object wrapping a C string derived from input.
           xmlXPathWrapCString takes ownership of the C string, so pass buf copy.
           We allocated 'buf' earlier as input copy; duplicate because the doc/node uses it. */
        char *str_for_wrap = strdup(buf ? buf : "");
        if (str_for_wrap != NULL) {
            xmlXPathObjectPtr obj = xmlXPathWrapCString(str_for_wrap);
            /* xmlXPathValuePush returns -1 on error; ignore the return value for fuzz harness */
            xmlXPathValuePush(pctxt, obj);
            /* Note: ownership of str_for_wrap is transferred to the XPath object */
        } else {
            /* If strdup failed, proceed with empty stack (function may still be exercised) */
        }
    }

    /* Call the target function under test */
    xmlXPathNumberFunction(pctxt, nargs);

    /* Cleanup: pop and release any remaining objects on the parser value stack */
    while (pctxt->valueNr > 0) {
        xmlXPathObjectPtr popped = xmlXPathValuePop(pctxt);
        if (popped != NULL)
            xmlXPathFreeObject(popped); /* use public API (non-static) */
    }

    /* Free parser context resources */
    free(pctxt->valueTab);
    free(pctxt);

    /* Free XPath context and document */
    xmlXPathFreeContext(xpath_ctxt);
    xmlFreeDoc(doc);

    /* Free the initial buffer copy (the one possibly duplicated and wrapped was transferred) */
    free(buf);

    return 0;
}
