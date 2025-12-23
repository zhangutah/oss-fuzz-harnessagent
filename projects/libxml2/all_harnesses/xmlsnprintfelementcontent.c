#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/valid.h>
#include <libxml/tree.h>

/*
 Fuzz driver for:
   void xmlSnprintfElementContent(char *buf, int size, xmlElementContent *content, int englob);
 Builds a small xmlElementContent tree from the fuzzer input and calls the target function.
 The parser is intentionally simple and bounded to avoid deep recursion or unbounded allocations.
*/

#define MAX_NODES 8
#define MAX_STR_LEN 64
#define OUT_BUF_SIZE 1024

/* Global registry of allocated nodes so we can free everything reliably
   even if the returned root does not reference all nodes. */
static xmlElementContent *g_nodes[MAX_NODES];
static size_t g_num_nodes = 0;

static xmlElementContent *
build_tree_from_data(const uint8_t *Data, size_t Size, int *out_englob) {
    if (!Data || Size == 0) return NULL;

    size_t pos = 0;

    /* Determine number of nodes (1..MAX_NODES) */
    size_t num_nodes = (Data[pos++] % MAX_NODES) + 1;
    if (pos >= Size) pos = Size; /* guard */

    xmlElementContent *nodes[MAX_NODES];
    memset(nodes, 0, sizeof(nodes));

    /* Reset global registry for this build; we'll register as we allocate. */
    g_num_nodes = 0;
    memset(g_nodes, 0, sizeof(g_nodes));

    /* Allocate nodes and fill fields deterministically from data */
    for (size_t i = 0; i < num_nodes; ++i) {
        xmlElementContent *n = (xmlElementContent *)calloc(1, sizeof(xmlElementContent));
        if (!n) {
            /* cleanup on allocation failure */
            for (size_t j = 0; j < i; ++j) {
                if (nodes[j]) {
                    if (nodes[j]->name) free((void *)nodes[j]->name);
                    if (nodes[j]->prefix) free((void *)nodes[j]->prefix);
                    free(nodes[j]);
                }
            }
            g_num_nodes = 0;
            return NULL;
        }
        /* Register allocation so free_tree can free it later */
        nodes[i] = n;
        if (g_num_nodes < MAX_NODES) g_nodes[g_num_nodes++] = n;

        /* type: map to 0..3 */
        if (pos < Size) n->type = (xmlElementContentType)(Data[pos++] % 4);
        else n->type = XML_ELEMENT_CONTENT_ELEMENT; /* default */

        /* ocur: map to 0..3 */
        if (pos < Size) n->ocur = (xmlElementContentOccur)(Data[pos++] % 4);
        else n->ocur = XML_ELEMENT_CONTENT_ONCE;

        /* name */
        size_t name_len = 0;
        if (pos < Size) name_len = Data[pos++] % (MAX_STR_LEN);
        if (name_len > 0) {
            char *name = (char *)malloc(name_len + 1);
            if (!name) name_len = 0;
            else {
                /* fill from data or deterministic filler */
                for (size_t k = 0; k < name_len; ++k) {
                    if (pos < Size) name[k] = (char)(Data[pos++] % 94 + 32);
                    else name[k] = 'a';
                }
                name[name_len] = '\0';
                n->name = (const xmlChar *)name;
            }
        } else {
            n->name = NULL;
        }

        /* prefix */
        size_t prefix_len = 0;
        if (pos < Size) prefix_len = Data[pos++] % (MAX_STR_LEN);
        if (prefix_len > 0) {
            char *prefix = (char *)malloc(prefix_len + 1);
            if (!prefix) prefix_len = 0;
            else {
                for (size_t k = 0; k < prefix_len; ++k) {
                    if (pos < Size) prefix[k] = (char)(Data[pos++] % 94 + 32);
                    else prefix[k] = 'p';
                }
                prefix[prefix_len] = '\0';
                n->prefix = (const xmlChar *)prefix;
            }
        } else {
            n->prefix = NULL;
        }

        n->c1 = NULL;
        n->c2 = NULL;
        n->parent = NULL;
    }

    /* Link children for SEQ or OR nodes.
       To avoid deep recursion, only link to nodes with index < i when possible. */
    for (size_t i = 0; i < num_nodes; ++i) {
        xmlElementContent *n = nodes[i];
        if (!n) continue;

        if (n->type == XML_ELEMENT_CONTENT_SEQ || n->type == XML_ELEMENT_CONTENT_OR) {
            /* choose c1 */
            if (i > 0) {
                size_t idx = 0;
                if (pos < Size) {
                    idx = Data[pos++] % i; /* pick from earlier nodes */
                } else {
                    idx = i - 1;
                }
                n->c1 = nodes[idx];
                if (nodes[idx]) nodes[idx]->parent = n;
            } else {
                n->c1 = NULL;
            }
            /* choose c2 */
            if (i > 0) {
                size_t idx = 0;
                if (pos < Size) {
                    idx = Data[pos++] % i;
                } else {
                    idx = i - 1;
                }
                n->c2 = nodes[idx];
                if (nodes[idx]) nodes[idx]->parent = n;
            } else {
                n->c2 = NULL;
            }
        } else {
            n->c1 = NULL;
            n->c2 = NULL;
        }
    }

    /* Post-process to ensure invariants required by xmlSnprintfElementContent:
       - ELEMENT nodes must have a non-NULL name because xmlSnprintfElementContent calls xmlStrlen(content->name)
         unconditionally for ELEMENT nodes.
       - SEQ/OR nodes must have non-NULL c1 and c2. If not, convert the node into ELEMENT with a default name.
    */
    for (size_t i = 0; i < num_nodes; ++i) {
        xmlElementContent *n = nodes[i];
        if (!n) continue;

        if (n->type == XML_ELEMENT_CONTENT_SEQ || n->type == XML_ELEMENT_CONTENT_OR) {
            if (n->c1 == NULL || n->c2 == NULL) {
                /* Convert to ELEMENT to avoid NULL derefs in the target function */
                n->type = XML_ELEMENT_CONTENT_ELEMENT;
                if (n->c1) n->c1->parent = NULL;
                if (n->c2) n->c2->parent = NULL;
                n->c1 = NULL;
                n->c2 = NULL;
                if (n->name == NULL) {
                    char *name = (char *)malloc(2);
                    if (name) { name[0] = 'a'; name[1] = '\0'; n->name = (const xmlChar *)name; }
                }
            }
        } else if (n->type == XML_ELEMENT_CONTENT_ELEMENT) {
            if (n->name == NULL) {
                /* Ensure ELEMENT nodes have a name */
                char *name = (char *)malloc(2);
                if (name) { name[0] = 'a'; name[1] = '\0'; n->name = (const xmlChar *)name; }
            }
        }
    }

    /* englob: derive from last byte if available */
    int englob = 0;
    if (Size >= 1) englob = Data[Size - 1] & 1;
    if (out_englob) *out_englob = englob;

    /* choose root: prefer the last allocated node (could be any) */
    xmlElementContent *root = nodes[num_nodes - 1];

    /* Note: we registered all allocated nodes in g_nodes[] so free_tree can free them later.
       Return the chosen root. */
    return root;
}

static void
free_tree(xmlElementContent *root) {
    (void)root; /* not needed: we'll free everything we recorded */

    if (g_num_nodes == 0) return;

    /* Free unique nodes and their name/prefix strings */
    for (size_t i = 0; i < g_num_nodes; ++i) {
        xmlElementContent *n = g_nodes[i];
        if (!n) continue;
        if (n->name) free((void *)n->name);
        if (n->prefix) free((void *)n->prefix);
        free(n);
        g_nodes[i] = NULL;
    }
    g_num_nodes = 0;
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0 || Data == NULL) return 0;

    int englob = 0;
    xmlElementContent *root = build_tree_from_data(Data, Size, &englob);
    if (!root) return 0;

    char out[OUT_BUF_SIZE];
    /* Initialize buffer with a small initial string derived from input to exercise early-size checks */
    size_t init_len = (Size > 1) ? (Data[0] % 48) : 0;
    if (init_len > 0) {
        for (size_t i = 0; i < init_len && i + 1 < Size; ++i) {
            /* printable characters */
            out[i] = (char)(Data[1 + i] % 94 + 32);
        }
        out[init_len] = '\0';
    } else {
        out[0] = '\0';
    }

    /* Call the target function. Provide a reasonably large buffer size to avoid actual overflow in fuzzer runs. */
    xmlSnprintfElementContent(out, OUT_BUF_SIZE, root, englob);

    /* Optionally, we could do something with out, but not necessary */
    (void)out;

    free_tree(root);
    return 0;
}
