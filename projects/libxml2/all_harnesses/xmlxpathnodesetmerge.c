#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

static xmlNodePtr
make_node(const uint8_t **pData, size_t *pSize, void **shared_next,
          int SHARED_NEXT_COUNT, void **allocs, int *alloc_count, int ALLOCS_MAX) {
    if (*pSize == 0) {
        /* default: simple element node */
        xmlNodePtr n = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
        if (n) {
            memset(n, 0, sizeof(xmlNode));
            n->type = XML_ELEMENT_NODE;
            /* record allocation */
            if (*alloc_count < ALLOCS_MAX) {
                allocs[(*alloc_count)++] = (void *)n;
            }
        }
        return n;
    }

    uint8_t flag = (*pData)[0];
    (*pData)++; (*pSize)--;

    if ((flag & 1) == 0) {
        /* Create a regular xmlNode */
        xmlNodePtr n = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
        if (n == NULL) return NULL;
        memset(n, 0, sizeof(xmlNode));
        /* record allocation */
        if (*alloc_count < ALLOCS_MAX) {
            allocs[(*alloc_count)++] = (void *)n;
        }
        /* Choose a non-namespace type for safety */
        const xmlElementType possible_types[] = {
            XML_ELEMENT_NODE, XML_TEXT_NODE, XML_CDATA_SECTION_NODE,
            XML_COMMENT_NODE, XML_PI_NODE
        };
        n->type = possible_types[(flag >> 1) % (sizeof(possible_types)/sizeof(possible_types[0]))];
        return n;
    } else {
        /* Create a namespace node (xmlNs) but return as xmlNodePtr */
        xmlNsPtr ns = (xmlNsPtr) xmlMalloc(sizeof(xmlNs));
        if (ns == NULL) return NULL;
        memset(ns, 0, sizeof(xmlNs));
#ifdef XML_NAMESPACE_DECL
        ns->type = XML_NAMESPACE_DECL;
#endif
        /* record allocation for ns struct */
        if (*alloc_count < ALLOCS_MAX) {
            allocs[(*alloc_count)++] = (void *)ns;
        }

        /* Choose a prefix from the remaining bytes (if any) */
        int plen = 0;
        if (*pSize > 0) {
            plen = (*pData)[0] % 8; /* up to length 7 */
            (*pData)++; (*pSize)--;
            if (plen > 0) {
                int avail = (int)(*pSize);
                int use = (plen < avail) ? plen : avail;
                xmlChar *dup = xmlStrndup((const xmlChar*)(*pData), use);
                if (dup != NULL) {
                    ns->prefix = dup;
                    /* record allocation for prefix string */
                    if (*alloc_count < ALLOCS_MAX) {
                        allocs[(*alloc_count)++] = (void *)dup;
                    }
                    (*pData) += use;
                    (*pSize) -= use;
                } else {
                    ns->prefix = NULL;
                }
            } else {
                ns->prefix = NULL;
            }
        } else {
            ns->prefix = NULL;
        }

        /* Choose a shared next pointer index to increase chance of equality */
        if (*pSize > 0 && SHARED_NEXT_COUNT > 0) {
            int si = (*pData)[0] % SHARED_NEXT_COUNT;
            ns->next = (xmlNsPtr) shared_next[si];
            (*pData)++; (*pSize)--;
        } else {
            ns->next = NULL;
        }

        return (xmlNodePtr) ns;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size < 2) return 0;

    size_t idx = 0;

    /* Determine counts from input bytes (kept small) */
    const int MAX_NODES_PER_SET = 16;
    int cnt1 = Data[idx++] % MAX_NODES_PER_SET;
    int cnt2 = Data[idx++] % MAX_NODES_PER_SET;

    /* Prepare a small pool of shared 'next' pointers for namespace nodes.
       Using a shared pointer increases the chance of triggering the
       namespace-duplicate detection branch in xmlXPathNodeSetMerge. */
    const int SHARED_NEXT_COUNT = 4;
    void *shared_next[SHARED_NEXT_COUNT];
    int i;

    /* Track all allocations so they can be freed once per-run (avoid leak across fuzzing iterations) */
    const int ALLOCS_MAX = 1024;
    void *allocs[ALLOCS_MAX];
    int alloc_count = 0;
    for (i = 0; i < ALLOCS_MAX; i++) allocs[i] = NULL;

    for (i = 0; i < SHARED_NEXT_COUNT; i++) {
        /* Allocate a tiny xmlNode to be used as a "next" target. */
        xmlNodePtr tmp = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
        if (tmp == NULL) {
            /* out of memory, bail out and free previously recorded allocations */
            int j;
            for (j = 0; j < alloc_count; j++) {
                if (allocs[j]) xmlFree(allocs[j]);
            }
            return 0;
        }
        memset(tmp, 0, sizeof(xmlNode));
        tmp->type = XML_ELEMENT_NODE;
        shared_next[i] = tmp;
        /* record allocation */
        if (alloc_count < ALLOCS_MAX) {
            allocs[alloc_count++] = (void *)tmp;
        } else {
            /* Unexpected, but to be safe free and stop storing to avoid overflow */
            xmlFree(tmp);
            shared_next[i] = NULL;
        }
    }

    /* Allocate and populate set1 and set2 node sets */
    xmlNodeSetPtr set1 = (xmlNodeSetPtr) xmlMalloc(sizeof(xmlNodeSet));
    xmlNodeSetPtr set2 = (xmlNodeSetPtr) xmlMalloc(sizeof(xmlNodeSet));
    if (set1 == NULL || set2 == NULL) {
        if (set1) xmlFree(set1);
        if (set2) xmlFree(set2);
        /* free recorded allocations */
        for (i = 0; i < alloc_count; i++) if (allocs[i]) xmlFree(allocs[i]);
        return 0;
    }
    memset(set1, 0, sizeof(xmlNodeSet));
    memset(set2, 0, sizeof(xmlNodeSet));

    /* Choose a sufficiently large nodeMax to avoid internal growth (and potential realloc complexities) */
    const int NODETAB_CAP = 64;
    set1->nodeMax = NODETAB_CAP;
    set2->nodeMax = NODETAB_CAP;

    set1->nodeTab = (xmlNodePtr *) xmlMalloc(sizeof(xmlNodePtr) * set1->nodeMax);
    set2->nodeTab = (xmlNodePtr *) xmlMalloc(sizeof(xmlNodePtr) * set2->nodeMax);
    if (set1->nodeTab == NULL || set2->nodeTab == NULL) {
        if (set1->nodeTab) xmlFree(set1->nodeTab);
        if (set2->nodeTab) xmlFree(set2->nodeTab);
        xmlFree(set1); xmlFree(set2);
        /* free recorded allocations */
        for (i = 0; i < alloc_count; i++) if (allocs[i]) xmlFree(allocs[i]);
        return 0;
    }
    /* initialize */
    for (i = 0; i < set1->nodeMax; i++) set1->nodeTab[i] = NULL;
    for (i = 0; i < set2->nodeMax; i++) set2->nodeTab[i] = NULL;

    set1->nodeNr = cnt1;
    set2->nodeNr = cnt2;

    /* Fill nodes using remaining Data bytes */
    const uint8_t *pdata = Data + idx;
    size_t pdata_rem = (idx <= Size) ? (Size - idx) : 0;

    for (i = 0; i < cnt1; i++) {
        xmlNodePtr n = make_node(&pdata, &pdata_rem, shared_next, SHARED_NEXT_COUNT,
                                 allocs, &alloc_count, ALLOCS_MAX);
        set1->nodeTab[i] = n;
    }
    for (i = 0; i < cnt2; i++) {
        xmlNodePtr n = make_node(&pdata, &pdata_rem, shared_next, SHARED_NEXT_COUNT,
                                 allocs, &alloc_count, ALLOCS_MAX);
        set2->nodeTab[i] = n;
    }

    /* Call the target function under test */
    (void) xmlXPathNodeSetMerge(set1, set2);

    /* Light cleanup: free top-level arrays and structs (but not individual node objects here).
       We will free all recorded allocations (nodes, prefixes, shared_next targets) below. */
    if (set1->nodeTab) xmlFree(set1->nodeTab);
    if (set2->nodeTab) xmlFree(set2->nodeTab);
    xmlFree(set1);
    xmlFree(set2);

    /* Free all unique recorded allocations */
    for (i = 0; i < alloc_count; i++) {
        void *p = allocs[i];
        if (p == NULL) continue;
        /* check if any previous entry had the same pointer to avoid double-free */
        int seen = 0;
        int j;
        for (j = 0; j < i; j++) {
            if (allocs[j] == p) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            xmlFree(p);
        }
    }

    return 0;
}
