#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Prefer absolute header path discovered for the target symbol */
#include "/src/libxml2/include/libxml/valid.h"

/*
 * Fuzz driver for:
 *   int xmlValidGetPotentialChildren(xmlElementContent * ctree,
 *                                    const xmlChar ** names,
 *                                    int * len, int max);
 *
 * The fuzzer entry point:
 *   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 *
 * Strategy:
 * - Interpret the input bytes as a compact description of a small tree
 *   of xmlElementContent nodes.
 * - Construct the nodes in heap memory, set their c1/c2/parent pointers
 *   according to indices encoded in the input.
 * - Ensure no cycles on c1/c2 by only pointing to nodes with index > i.
 * - Provide a names buffer and len pointer and call the target function.
 * - Clean up allocations and return.
 *
 * Input layout (consumed sequentially):
 *   [0]           : n_nodes_encoded (0 -> 0 nodes => immediate return)
 *   For each node (repeated n_nodes times):
 *     1 byte      : type (0..255) => mapped to xmlElementContentType (1..4)
 *     1 byte      : ocur (0..255) => mapped to xmlElementContentOccur (1..4)
 *     1 byte      : name_len (0..MAX_NAME_LEN)
 *     name_len b  : name bytes (not NUL-terminated in input)
 *     1 byte      : c1_index (0xFF => NULL, otherwise index % n_nodes)
 *     1 byte      : c2_index (0xFF => NULL, otherwise index % n_nodes)
 *     1 byte      : parent_index (0xFF => NULL, otherwise index % n_nodes)
 *   After nodes, optionally one byte chooses root index (0..n_nodes-1) (if present)
 *
 * All indices are interpreted modulo n_nodes when not 0xFF.
 *
 * Notes:
 * - We bound sizes to avoid excessive allocation.
 * - The structure xmlElementContent is defined by libxml2 headers included above.
 */

#define MAX_NODES 64
#define MAX_NAME_LEN 128
#define MAX_NAMES 256

static inline uint8_t consume_u8(const uint8_t *Data, size_t Size, size_t *pos, int *ok) {
    if (!ok) return 0;
    if (*pos >= Size) { *ok = 0; return 0; }
    return Data[(*pos)++];
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    size_t pos = 0;
    int ok = 1;

    uint8_t n_nodes_enc = consume_u8(Data, Size, &pos, &ok);
    if (!ok) return 0;

    /* Map to a reasonable node count */
    int n_nodes = (n_nodes_enc % MAX_NODES);
    if (n_nodes <= 0) return 0; /* nothing to do */

    /* Allocate an array of xmlElementContent on the heap */
    xmlElementContent *nodes = (xmlElementContent *)calloc((size_t)n_nodes, sizeof(xmlElementContent));
    if (!nodes) return 0;

    /* Keep allocated name buffers to free later */
    unsigned char *name_bufs[MAX_NODES];
    memset(name_bufs, 0, sizeof(name_bufs));

    /* Temporarily store indices for c1/c2/parent until we can fix pointers */
    int *c1_idx = (int *)malloc(sizeof(int) * (size_t)n_nodes);
    int *c2_idx = (int *)malloc(sizeof(int) * (size_t)n_nodes);
    int *parent_idx = (int *)malloc(sizeof(int) * (size_t)n_nodes);
    if (!c1_idx || !c2_idx || !parent_idx) {
        free(nodes);
        free(c1_idx); free(c2_idx); free(parent_idx);
        return 0;
    }

    for (int i = 0; i < n_nodes; i++) {
        if (!ok) break;

        uint8_t t = consume_u8(Data, Size, &pos, &ok);
        if (!ok) break;
        uint8_t ocur = consume_u8(Data, Size, &pos, &ok);
        if (!ok) break;
        uint8_t name_len = consume_u8(Data, Size, &pos, &ok);
        if (!ok) break;

        if (name_len > MAX_NAME_LEN) name_len = (uint8_t)(name_len % (MAX_NAME_LEN + 1));

        /* allocate and copy name (xmlChar is unsigned char) */
        unsigned char *nbuf = NULL;
        if (name_len > 0) {
            nbuf = (unsigned char *)malloc((size_t)name_len + 1);
            if (!nbuf) { ok = 0; break; }
            /* If not enough bytes available, fill with zeros for remaining */
            size_t remaining = Size - pos;
            size_t to_copy = name_len <= remaining ? name_len : remaining;
            if (to_copy) memcpy(nbuf, Data + pos, to_copy);
            if (to_copy < name_len) memset(nbuf + to_copy, 0, (size_t)(name_len - to_copy));
            nbuf[name_len] = '\0';
            pos += to_copy;
        }

        uint8_t idx_c1 = consume_u8(Data, Size, &pos, &ok);
        if (!ok) { free(nbuf); break; }
        uint8_t idx_c2 = consume_u8(Data, Size, &pos, &ok);
        if (!ok) { free(nbuf); break; }
        uint8_t idx_parent = consume_u8(Data, Size, &pos, &ok);
        if (!ok) { free(nbuf); break; }

        /* Fill node fields */
        nodes[i].type = (xmlElementContentType)((t % 4) + 1); /* 1..4 */
        nodes[i].ocur = (xmlElementContentOccur)((ocur % 4) + 1); /* 1..4 */
        nodes[i].name = nbuf ? (const xmlChar *)nbuf : NULL;
        nodes[i].c1 = NULL;
        nodes[i].c2 = NULL;
        nodes[i].parent = NULL;
        nodes[i].prefix = NULL;

        name_bufs[i] = nbuf;

        /* Store indices; 0xFF => NULL */
        c1_idx[i] = (idx_c1 == 0xFF) ? -1 : (int)(idx_c1 % (uint8_t)n_nodes);
        c2_idx[i] = (idx_c2 == 0xFF) ? -1 : (int)(idx_c2 % (uint8_t)n_nodes);
        parent_idx[i] = (idx_parent == 0xFF) ? -1 : (int)(idx_parent % (uint8_t)n_nodes);
    }

    if (!ok) {
        for (int i = 0; i < n_nodes; i++) free(name_bufs[i]);
        free(nodes);
        free(c1_idx); free(c2_idx); free(parent_idx);
        return 0;
    }

    /* Fix pointer relations using stored indices.
     * To avoid cycles that lead to infinite recursion in the caller,
     * only allow c1 and c2 pointers to point to nodes with an index > i.
     * This ensures the c1/c2 graph is acyclic (edges go forward).
     */
    for (int i = 0; i < n_nodes; i++) {
        if (c1_idx[i] >= 0 && c1_idx[i] < n_nodes && c1_idx[i] > i)
            nodes[i].c1 = &nodes[c1_idx[i]];
        else
            nodes[i].c1 = NULL;

        if (c2_idx[i] >= 0 && c2_idx[i] < n_nodes && c2_idx[i] > i)
            nodes[i].c2 = &nodes[c2_idx[i]];
        else
            nodes[i].c2 = NULL;

        /* parent is not used by xmlValidGetPotentialChildren itself; set if in-range */
        if (parent_idx[i] >= 0 && parent_idx[i] < n_nodes)
            nodes[i].parent = &nodes[parent_idx[i]];
        else
            nodes[i].parent = NULL;
    }

    /* Choose a root index if available from input, otherwise use 0 */
    int root_idx = 0;
    if (pos < Size) {
        uint8_t r = Data[pos++];
        root_idx = (int)(r % (uint8_t)n_nodes);
    }

    xmlElementContent *ctree = &nodes[root_idx];

    /* Prepare output buffer for names and length */
    const xmlChar *out_names[MAX_NAMES];
    int out_len = 0;
    int max = MAX_NAMES;

    /* Call the target function */
    (void)xmlValidGetPotentialChildren(ctree, out_names, &out_len, max);

    /* Cleanup */
    for (int i = 0; i < n_nodes; i++) {
        free(name_bufs[i]);
    }
    free(nodes);
    free(c1_idx);
    free(c2_idx);
    free(parent_idx);

    return 0;
}
