#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/*
 * Fuzzer entry point for xmlXPathSumFunction:
 *   void xmlXPathSumFunction(xmlXPathParserContext * ctxt, int nargs);
 *
 * This harness:
 * - Initializes libxml2.
 * - Builds a small xmlDoc with up to a few child nodes whose text content
 *   are integer strings derived from the fuzzer input bytes.
 * - Creates a minimal xmlXPathParserContext with an xmlXPathObject node-set
 *   containing those nodes on the parser value stack.
 * - Calls xmlXPathSumFunction(&parser, 1).
 * - Cleans up.
 *
 * The goal is to exercise xmlXPathSumFunction including its conversion of
 * node string-values to numbers and summation logic.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser environment (safe to call multiple times). */
    xmlInitParser();

    /* Create a small document */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1");
    if (doc == NULL)
        return 0;

    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }
    xmlDocSetRootElement(doc, root);

    /* Limit the number of nodes to keep harness simple */
    const size_t max_nodes = 16;
    size_t node_count = (Size < max_nodes) ? Size : max_nodes;

    /* Create child nodes with textual content derived from input bytes.
       Use decimal representation of each byte so xmlXPathNodeToNumberInternal
       will convert them to numbers. */
    xmlNodePtr nodes[max_nodes];
    for (size_t i = 0; i < node_count; ++i) {
        char buf[4]; /* enough for 0..255 + NUL */
        snprintf(buf, sizeof(buf), "%u", (unsigned)Data[i]);
        nodes[i] = xmlNewChild(root, NULL, BAD_CAST "n", BAD_CAST buf);
        if (nodes[i] == NULL) {
            /* If creation failed, reduce node_count and continue safely */
            node_count = i;
            break;
        }
    }

    /* Allocate a parser context on the heap (xmlXPathFreeParserContext
       calls xmlFree(ctxt), so ctxt must be heap-allocated). */
    xmlXPathParserContext *parser = (xmlXPathParserContext *)xmlMalloc(sizeof(xmlXPathParserContext));
    if (parser == NULL) {
        /* cleanup nodes/doc */
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    memset(parser, 0, sizeof(*parser));

    /* Create an evaluation context and attach the doc */
    parser->context = xmlXPathNewContext(doc);
    if (parser->context == NULL) {
        /* cleanup nodes/doc/parser */
        xmlFree(parser);
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Prepare an xmlXPathObject that is a node-set containing the created nodes.
       Use xmlXPathNewNodeSet for the first node and then add others. */
    xmlXPathObjectPtr obj = NULL;
    if (node_count > 0) {
        obj = xmlXPathNewNodeSet(nodes[0]);
        if (obj == NULL) {
            xmlXPathFreeContext(parser->context);
            xmlFree(parser);
            xmlFreeDoc(doc);
            xmlCleanupParser();
            return 0;
        }
        for (size_t i = 1; i < node_count; ++i) {
            if (nodes[i] != NULL)
                xmlXPathNodeSetAdd(obj->nodesetval, nodes[i]);
        }
    } else {
        /* Create an empty node-set object */
        obj = xmlXPathNewNodeSet(NULL);
        if (obj == NULL) {
            xmlXPathFreeContext(parser->context);
            xmlFree(parser);
            xmlFreeDoc(doc);
            xmlCleanupParser();
            return 0;
        }
    }

    /* Prepare the parser's value stack to contain the node-set object */
    parser->valueMax = 1;
    parser->valueTab = (xmlXPathObjectPtr *) xmlMalloc(sizeof(xmlXPathObjectPtr) * parser->valueMax);
    if (parser->valueTab == NULL) {
        /* cleanup: use public free function instead of internal static one */
        xmlXPathFreeObject(obj);
        xmlXPathFreeContext(parser->context);
        xmlFree(parser);
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    parser->valueTab[0] = obj;
    parser->valueNr = 1;
    parser->value = obj;

    /* Call the function under test with nargs == 1 (CHECK_ARITY(1) in implementation) */
    xmlXPathSumFunction(parser, 1);

    /*
     * After xmlXPathSumFunction returns:
     * - It pops the node-set object we put on the parser stack (xmlXPathValuePop),
     *   computes the sum, pushes a float xmlXPathObject onto the stack and then
     *   releases the popped object (xmlXPathReleaseObject).
     *
     * To properly clean up everything, free the parser context which will
     * release any remaining values and internal allocations, then free the
     * evaluation context, document and cleanup parser.
     */

    /* Save the evaluation context pointer because xmlXPathFreeParserContext
       will free 'parser' memory (but does not free parser->context). */
    xmlXPathContextPtr saved_eval_ctx = parser->context;

    /* Free the parser internal structures (declared in xpathInternals.h).
       This will free parser (xmlFree) so don't access 'parser' after this. */
    xmlXPathFreeParserContext(parser);

    /* Free the evaluation context and the document */
    if (saved_eval_ctx)
        xmlXPathFreeContext(saved_eval_ctx);
    xmlFreeDoc(doc);

    /* Cleanup libxml2 global state for this harness invocation */
    xmlCleanupParser();

    return 0;
}
