#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Ensure the Relax-NG part of the compilation unit is enabled when
// including the implementation file.
#ifndef LIBXML_RELAXNG_ENABLED
#define LIBXML_RELAXNG_ENABLED
#endif

// Include the implementation to get access to the static function.
// Use the project's absolute path returned by the code search tools.
#include "/src/libxml2/relaxng.c"

// Helper: a small capped allocator for xmlRelaxNGDefine nodes built from
// fuzz input. We create simple nodes with minimal fields set (type,
// dflags, content, next). Other pointers (node, name, ns, value, data,
// contModel) are left NULL which is safe for xmlRelaxNGIsNullable.
static xmlRelaxNGDefinePtr *build_nodes_from_data(const uint8_t *Data, size_t Size, int *out_count) {
    if (Data == NULL || Size == 0) {
        *out_count = 0;
        return NULL;
    }

    // Cap the number of nodes to avoid deep recursion and excessive memory use.
    const int MAX_NODES = 16;
    // Use first byte to pick number of nodes (at least 1)
    size_t pos = 0;
    int n = 1;
    if (pos < Size) {
        n = 1 + (Data[pos] % 8); // create between 1 and 8 nodes by default
        pos++;
    }
    if (n > MAX_NODES) n = MAX_NODES;
    if (n < 1) n = 1;

    xmlRelaxNGDefinePtr *nodes = (xmlRelaxNGDefinePtr *)calloc(n, sizeof(xmlRelaxNGDefinePtr));
    if (nodes == NULL) {
        *out_count = 0;
        return NULL;
    }

    // Allocate and zero-initialize each node
    for (int i = 0; i < n; i++) {
        nodes[i] = (xmlRelaxNGDefinePtr)calloc(1, sizeof(struct _xmlRelaxNGDefine));
        if (nodes[i] == NULL) {
            // free already allocated
            for (int j = 0; j < i; j++) free(nodes[j]);
            free(nodes);
            *out_count = 0;
            return NULL;
        }
        // Initialize fields that we will use:
        nodes[i]->type = XML_RELAXNG_EMPTY;
        nodes[i]->dflags = 0;
        nodes[i]->content = NULL;
        nodes[i]->next = NULL;
    }

    // Table of candidate types to pick from using fuzz bytes.
    int type_table[] = {
        XML_RELAXNG_EMPTY,
        XML_RELAXNG_TEXT,
        XML_RELAXNG_NOOP,
        XML_RELAXNG_DEF,
        XML_RELAXNG_REF,
        XML_RELAXNG_EXTERNALREF,
        XML_RELAXNG_PARENTREF,
        XML_RELAXNG_ONEORMORE,
        XML_RELAXNG_EXCEPT,
        XML_RELAXNG_NOT_ALLOWED,
        XML_RELAXNG_ELEMENT,
        XML_RELAXNG_DATATYPE,
        XML_RELAXNG_PARAM,
        XML_RELAXNG_VALUE,
        XML_RELAXNG_LIST,
        XML_RELAXNG_ATTRIBUTE,
        XML_RELAXNG_CHOICE,
        XML_RELAXNG_START,
        XML_RELAXNG_INTERLEAVE,
        XML_RELAXNG_GROUP
    };
    const int TYPE_TABLE_SZ = sizeof(type_table) / sizeof(type_table[0]);

    // Fill node fields using bytes from Data.
    for (int i = 0; i < n; i++) {
        // pick type
        if (pos < Size) {
            nodes[i]->type = (xmlRelaxNGType)type_table[Data[pos] % TYPE_TABLE_SZ];
            pos++;
        } else {
            // cycle through types deterministically if input exhausted
            nodes[i]->type = (xmlRelaxNGType)type_table[i % TYPE_TABLE_SZ];
        }

        // dflags: use next byte if available
        if (pos < Size) {
            uint8_t b = Data[pos++];
            // Map some bits to dflags used by xmlRelaxNGIsNullable
            if (b & 0x1) nodes[i]->dflags |= IS_NULLABLE;
            if (b & 0x2) nodes[i]->dflags |= IS_NOT_NULLABLE;
            // keep other bits 0
        }

        // content pointer: for node kinds that may use content or a list,
        // choose another node (forward-only) or NULL based on next byte.
        if (pos < Size) {
            uint8_t b = Data[pos++];
            if (b % 3 == 0) {
                // point content to the next node if available (no wrap)
                if ((i + 1) < n) {
                    nodes[i]->content = nodes[i + 1];
                } else {
                    nodes[i]->content = NULL;
                }
            } else if (b % 3 == 1) {
                // make content a small list starting at next node
                if ((i + 1) < n) {
                    nodes[i]->content = nodes[i + 1];
                    // chain one or two nodes optionally but only forward
                    if ((i + 2) < n && (b & 0x2)) {
                        nodes[i]->content->next = nodes[i + 2];
                    }
                } else {
                    nodes[i]->content = NULL;
                }
            } else {
                // leave content NULL
                nodes[i]->content = NULL;
            }
        } else {
            nodes[i]->content = NULL;
        }

        // next pointer: optionally link to the following allocated node to
        // create lists used by CHOICE/GROUP/INTERLEAVE etc. Do not wrap.
        if (pos < Size) {
            uint8_t b = Data[pos++];
            if ((b & 0x1) && (i + 1) < n) {
                nodes[i]->next = nodes[i + 1];
            } else {
                nodes[i]->next = NULL;
            }
        } else {
            nodes[i]->next = NULL;
        }
    }

    *out_count = n;
    return nodes;
}

static void free_nodes(xmlRelaxNGDefinePtr *nodes, int count) {
    if (nodes == NULL) return;
    for (int i = 0; i < count; i++) {
        if (nodes[i]) free(nodes[i]);
    }
    free(nodes);
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Basic validation
    if (Data == NULL || Size == 0) return 0;

    // Build a small set of xmlRelaxNGDefine nodes from the input.
    int count = 0;
    xmlRelaxNGDefinePtr *nodes = build_nodes_from_data(Data, Size, &count);
    if (nodes == NULL || count == 0) return 0;

    // Use the first node as the root define to test.
    xmlRelaxNGDefinePtr root = nodes[0];

    // Call the target function. It may set dflags on the structures; that's fine.
    // Wrap calls in a small loop to exercise different code paths if input allows.
    // We compute an iteration count from the next byte (if any) but cap it.
    size_t iters = 1;
    if (Size > 1) iters = 1 + (Data[1] % 4);
    if (iters == 0) iters = 1;
    for (size_t i = 0; i < iters; i++) {
        // Call the function under test (static function included via relaxng.c).
        // The function returns -1, 0 or 1. We don't assert anything here; the
        // fuzzer will monitor for crashes/UB.
        (void)xmlRelaxNGIsNullable(root);
    }

    // Free allocated nodes and exit.
    free_nodes(nodes, count);

    return 0;
}
