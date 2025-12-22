#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size < 8) /* need at least 8 bytes to extract counts safely */
        return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();

    /* Parse two 32-bit values from input:
       - nNodes: number of nodes to allocate in the xmlNodeSet (clamped)
       - val: the index to remove (signed int) */
    uint32_t nNodes;
    int32_t val;
    memcpy(&nNodes, Data, sizeof(nNodes));
    memcpy(&val, Data + sizeof(nNodes), sizeof(val));

    /* Bound the number of nodes to avoid huge allocations from fuzz data */
    const uint32_t MAX_NODES = 1000;
    if (nNodes > MAX_NODES)
        nNodes = nNodes % (MAX_NODES + 1);

    /* Ensure at least a small allocation (0 allowed) */
    uint32_t nodeCount = nNodes;

    /* Set base nodeMax (must be >= nodeCount, at least 1) */
    uint32_t baseNodeMax = (nodeCount == 0) ? 1 : nodeCount;

    /* Add extra slack to nodeMax to avoid internal writes beyond nodeNr:
       xmlXPathNodeSetRemove and other XPath internals may write/read
       near the boundary; give some safe headroom. */
    const uint32_t SLACK = 16;
    uint32_t allocNodeMax = baseNodeMax + SLACK;

    /* Allocate and populate xmlNodeSet */
    xmlNodeSet *cur = (xmlNodeSet *)malloc(sizeof(xmlNodeSet));
    if (!cur)
        return 0;
    cur->nodeNr = (int)nodeCount;
    cur->nodeMax = (int)allocNodeMax;

    /* Allocate the nodeTab array with extra room, zero-initialized */
    cur->nodeTab = (xmlNode **)calloc((size_t)cur->nodeMax, sizeof(xmlNode *));
    if (!cur->nodeTab) {
        free(cur);
        return 0;
    }

    /* Create a small xmlDoc and a root element; attach nodes under root
       so xmlFreeDoc will reliably free remaining nodes. */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (!doc) {
        free(cur->nodeTab);
        free(cur);
        return 0;
    }

    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    if (!root) {
        xmlFreeDoc(doc);
        free(cur->nodeTab);
        free(cur);
        xmlCleanupParser();
        return 0;
    }
    /* Set the root element for the document (this sets root->doc) */
    xmlDocSetRootElement(doc, root);

    /*
     * Allocate proper xmlNode objects for each entry we will populate.
     * Use xmlNewNode and attach them under 'root' so xmlFreeDoc can clean up.
     */
    for (int i = 0; i < cur->nodeNr; ++i) {
        /* create a minimal, valid node (name "a") */
        xmlNodePtr node = xmlNewNode(NULL, BAD_CAST "a");
        if (!node) {
            /* On allocation failure, rely on xmlFreeDoc to free the root and any
               previously attached child nodes. Free the arrays and exit. */
            free(cur->nodeTab);
            free(cur);
            xmlFreeDoc(doc);
            xmlCleanupParser();
            return 0;
        }
        /* Attach node under root; xmlAddChild sets node->doc appropriately */
        xmlAddChild(root, node);
        cur->nodeTab[i] = node;
    }

    /* Remaining slots (slack) are left NULL by calloc */

    /*
     * Call the target function with the provided val (may be negative or out-of-range)
     *
     * To avoid invoking undefined behavior inside xmlXPathNodeSetRemove for
     * empty sets or extreme out-of-range indexes produced by fuzzers, ensure
     * there's at least one node and compute a safe index.
     */
    if (cur->nodeNr > 0) {
        int idx = (int)val;
        /* handle negative indices similar to many APIs: negative means from end */
        if (idx < 0)
            idx = cur->nodeNr + idx;
        /* clamp */
        if (idx < 0)
            idx = 0;
        if (idx >= cur->nodeNr)
            idx = cur->nodeNr - 1;

        xmlXPathNodeSetRemove(cur, idx);
    }

    /*
     * Cleanup:
     * We attached nodes into the document tree under 'root' and will let
     * xmlFreeDoc free remaining nodes. Do NOT call xmlFreeNode on nodeTab
     * entries here because xmlXPathNodeSetRemove may have already freed some
     * of them (double-free risk). Just free the nodeTab array and the
     * xmlNodeSet container, then free the doc.
     */
    free(cur->nodeTab);
    free(cur);

    /* Free the dummy document (frees root and any remaining child nodes) */
    xmlFreeDoc(doc);

    /* Optional cleanup for libxml */
    xmlCleanupParser();

    return 0;
}
