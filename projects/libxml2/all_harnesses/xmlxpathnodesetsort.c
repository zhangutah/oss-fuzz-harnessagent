#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Use absolute project headers discovered for the target symbol */
#include "/src/libxml2/include/libxml/xpathInternals.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzz driver for:
     void xmlXPathNodeSetSort(xmlNodeSet * set);

 Entry point expected by libFuzzer:
     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

#ifndef MAX_FUZZ_NODES
#define MAX_FUZZ_NODES 64
#endif

/* Helper to safely consume bytes from the input */
static inline unsigned int
consume_byte(const uint8_t **data, size_t *size) {
    if (*size == 0) return 0;
    unsigned int v = (*data)[0];
    (*data)++;
    (*size)--;
    return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Work on a local copy of the data pointer so we can consume bytes */
    const uint8_t *p = Data;
    size_t rem = Size;

    /* Determine number of nodes to create (1..MAX_FUZZ_NODES) */
    unsigned int raw_count = consume_byte(&p, &rem);
    size_t node_count = (raw_count % MAX_FUZZ_NODES) + 1;

    /* Allocate array to hold pointers to created xmlNode objects */
    xmlNodePtr *nodes = (xmlNodePtr *)calloc(node_count, sizeof(xmlNodePtr));
    if (nodes == NULL)
        return 0;

    /*
     * Create a minimal fake document to assign to node->doc so code
     * that expects a non-NULL doc won't dereference NULL.
     */
    xmlDocPtr fake_doc = (xmlDocPtr)calloc(1, sizeof(xmlDoc));
    if (fake_doc == NULL) {
        free(nodes);
        return 0;
    }
    fake_doc->doc = fake_doc; /* self reference is common in libxml2 docs */
    fake_doc->type = XML_DOCUMENT_NODE;

    /* A small palette of node types to pick from.
     * Avoid XML_NAMESPACE_DECL and XML_ATTRIBUTE_NODE which have a different
     * underlying layout and can lead to UB when allocated as xmlNode.
     */
    xmlElementType type_palette[] = {
        XML_ELEMENT_NODE,
        XML_TEXT_NODE,
        XML_CDATA_SECTION_NODE,
        XML_COMMENT_NODE,
        XML_DOCUMENT_NODE
    };
    const size_t palette_len = sizeof(type_palette) / sizeof(type_palette[0]);

    /* Create nodes and initialize minimal fields used by xmlXPathCmpNodes / sort */
    for (size_t i = 0; i < node_count; ++i) {
        xmlNodePtr n = (xmlNodePtr)calloc(1, sizeof(xmlNode));
        if (n == NULL) {
            /* cleanup allocated so far */
            for (size_t j = 0; j < i; ++j) {
                if (nodes[j]) {
                    if (nodes[j]->name) free((void *)nodes[j]->name);
                    free(nodes[j]);
                }
            }
            free(nodes);
            free(fake_doc);
            return 0;
        }

        /* Choose a type from the palette using next byte(s) if available */
        unsigned int b = consume_byte(&p, &rem);
        n->type = type_palette[b % palette_len];

        /*
         * Set prev/next to form a doubly-linked list across the nodeTab order.
         * These will be fixed to real pointers after all nodes are allocated.
         */
        n->prev = (i == 0) ? NULL : (xmlNodePtr)0x1; /* placeholder; will fix after all nodes allocated */
        n->next = (i + 1 < node_count) ? (xmlNodePtr)0x1 : NULL; /* placeholder */

        /* Assign a minimal document pointer to avoid NULL derefs in comparisons */
        n->doc = fake_doc;

        /*
         * Optionally set a small name string using remaining input bytes.
         * xmlChar is unsigned char, so cast accordingly.
         */
        if (rem > 0) {
            unsigned int name_len = consume_byte(&p, &rem) % 8; /* up to 7 chars */
            if (name_len > 0) {
                char *s = (char *)malloc(name_len + 1);
                if (s) {
                    unsigned int k = 0;
                    for (; k < name_len && rem > 0; ++k) {
                        unsigned int vb = consume_byte(&p, &rem);
                        s[k] = (char)(32 + (vb % 95)); /* printable range */
                    }
                    /* If we couldn't fill whole requested name_len because input ended,
                     * ensure the string is properly terminated.
                     */
                    s[k] = '\0';
                    n->name = (const xmlChar *)s;
                } else {
                    n->name = NULL;
                }
            } else {
                n->name = NULL;
            }
        } else {
            n->name = NULL;
        }

        nodes[i] = n;
    }

    /* Now fix prev/next to point to actual node pointers */
    for (size_t i = 0; i < node_count; ++i) {
        nodes[i]->prev = (i == 0) ? NULL : nodes[i - 1];
        nodes[i]->next = (i + 1 < node_count) ? nodes[i + 1] : NULL;
    }

    /*
     * Set parent pointers. Use input bytes to select a parent index or NULL.
     * Avoid self-parenting.
     */
    for (size_t i = 0; i < node_count; ++i) {
        if (rem == 0) {
            nodes[i]->parent = NULL;
        } else {
            unsigned int v = consume_byte(&p, &rem);
            size_t pick = v % (node_count + 1); /* last value means NULL */
            if (pick == node_count || pick == i) {
                nodes[i]->parent = NULL;
            } else {
                nodes[i]->parent = nodes[pick];
            }
        }
    }

    /* Build a minimal xmlNodeSet and fill nodeTab */
    xmlNodeSetPtr set = (xmlNodeSetPtr)calloc(1, sizeof(xmlNodeSet));
    if (set == NULL) {
        for (size_t i = 0; i < node_count; ++i) {
            if (nodes[i]) {
                if (nodes[i]->name) free((void *)nodes[i]->name);
                free(nodes[i]);
            }
        }
        free(nodes);
        free(fake_doc);
        return 0;
    }

    set->nodeNr = (int)node_count;
    set->nodeMax = (int)node_count;
    set->nodeTab = (xmlNodePtr *)calloc(node_count, sizeof(xmlNodePtr));
    if (set->nodeTab == NULL) {
        free(set);
        for (size_t i = 0; i < node_count; ++i) {
            if (nodes[i]) {
                if (nodes[i]->name) free((void *)nodes[i]->name);
                free(nodes[i]);
            }
        }
        free(nodes);
        free(fake_doc);
        return 0;
    }

    for (size_t i = 0; i < node_count; ++i)
        set->nodeTab[i] = nodes[i];

    /*
     * CALL TARGET FUNCTION:
     * Sort the node set in document order. Fuzzing aims to exercise various
     * comparison paths within xmlXPathCmpNodes and the sort implementation.
     */
    xmlXPathNodeSetSort(set);

    /*
     * Cleanup - free allocated node names, nodes, nodeTab and set.
     * Note: xmlNode contains pointers to other structures (doc, children, ...)
     * that we didn't allocate; freeing only what we allocated is safe here.
     */
    for (size_t i = 0; i < node_count; ++i) {
        if (nodes[i]) {
            if (nodes[i]->name)
                free((void *)nodes[i]->name);
            free(nodes[i]);
        }
    }
    free(set->nodeTab);
    free(set);
    free(nodes);

    /* free our fake doc */
    free(fake_doc);

    return 0;
}
