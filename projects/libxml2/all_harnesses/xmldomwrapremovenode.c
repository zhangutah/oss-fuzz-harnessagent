#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 Fuzz driver for:
   int xmlDOMWrapRemoveNode(xmlDOMWrapCtxt * ctxt, xmlDoc * doc, xmlNode * node, int options);
 Fuzzer entrypoint:
   int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
*/

static void
collect_nodes(xmlNodePtr node, xmlNodePtr **out, size_t *cnt, size_t *cap) {
    for (xmlNodePtr cur = node; cur != NULL; cur = cur->next) {
        if (*cnt >= *cap) {
            size_t newcap = (*cap == 0) ? 64 : (*cap * 2);
            xmlNodePtr *tmp = (xmlNodePtr *)realloc(*out, newcap * sizeof(xmlNodePtr));
            if (tmp == NULL) {
                /* Allocation failure: stop collecting */
                return;
            }
            *out = tmp;
            *cap = newcap;
        }
        (*out)[(*cnt)++] = cur;
        if (cur->children)
            collect_nodes(cur->children, out, cnt, cap);
        /* Note: attributes (properties) are not traversed here. */
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize parser (safe to call multiple times) */
    xmlInitParser();

    if (Data == NULL || Size == 0)
        return 0;

    /* Parse input as an XML document in-memory */
    /* Use 0 for options to keep behavior portable; parsers may handle malformed input. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL, 0);
    if (doc == NULL) {
        /* Clean up parser globals allocated by xmlInitParser if any */
        xmlCleanupParser();
        return 0;
    }

    /* Get the root and collect nodes */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    xmlNodePtr *nodes = NULL;
    size_t count = 0, cap = 0;
    collect_nodes(root, &nodes, &count, &cap);

    if (count == 0) {
        free(nodes);
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Build list of candidate nodes that have a parent (xmlDOMWrapRemoveNode expects parent != NULL for meaningful work) */
    xmlNodePtr *candidates = NULL;
    size_t cand_cnt = 0, cand_cap = 0;
    for (size_t i = 0; i < count; ++i) {
        xmlNodePtr n = nodes[i];
        if (n != NULL && n->parent != NULL && n->doc == doc) {
            if (cand_cnt >= cand_cap) {
                size_t newcap = (cand_cap == 0) ? 32 : (cand_cap * 2);
                xmlNodePtr *tmp = (xmlNodePtr *)realloc(candidates, newcap * sizeof(xmlNodePtr));
                if (tmp == NULL) break;
                candidates = tmp;
                cand_cap = newcap;
            }
            candidates[cand_cnt++] = n;
        }
    }

    if (cand_cnt > 0) {
        /* Choose a candidate based on input bytes to get deterministic but varied picks */
        size_t idx = ((size_t)Data[0]) % cand_cnt;
        xmlNodePtr target = candidates[idx];

        /* Call the target function. Pass NULL for ctxt (allowed by implementation). */
        (void)xmlDOMWrapRemoveNode(NULL, doc, target, 0);
        /* The call may unlink the node from the tree; freeing the doc below will clean up. */
    }

    /* Cleanup */
    free(nodes);
    free(candidates);
    xmlFreeDoc(doc);

    /*
     * Free parser global state to avoid persistent allocations between fuzz iterations.
     * This prevents the LeakSanitizer reports about parser allocations that would otherwise
     * remain until process termination.
     */
    xmlCleanupParser();

    return 0;
}
