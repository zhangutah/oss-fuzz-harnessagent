// SPDX-License-Identifier: MIT
// Fuzz driver for: int xmlRelaxNGIsCompilable(xmlRelaxNGDefinePtr def);
// Fuzzer entry point: LLVMFuzzerTestOneInput

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xmlstring.h>
#include <libxml/xmlmemory.h>
#include <libxml/relaxng.h>

// Ensure the RelaxNG implementation is compiled into this TU so we can call
// the (internal) xmlRelaxNGIsCompilable implementation from relaxng.c.
#define LIBXML_RELAXNG_ENABLED
// Include the implementation directly so internal types and the (static)
// xmlRelaxNGIsCompilable function are available in this translation unit.
// Path is relative to fuzz/regexp.c location.
#include "../relaxng.c"

// Helper: safely read a byte from Data or return 0 if out-of-range.
static unsigned char read_byte(const uint8_t *Data, size_t Size, size_t pos) {
    if (pos >= Size) return 0;
    return Data[pos];
}

// Helper: create an xmlChar* string from Data at offset with length len.
// Uses xmlStrndup which uses libxml allocation functions.
static xmlChar *dup_xmlchar_from_input(const uint8_t *Data, size_t Size, size_t *pos,
                                       size_t maxLen) {
    if (*pos >= Size) return NULL;
    size_t remaining = Size - *pos;
    size_t len = remaining < maxLen ? remaining : maxLen;
    if (len == 0) return NULL;
    // Limit len further by consuming a length byte if available:
    // If there's at least one byte, use it to determine desired len.
    unsigned char requested = read_byte(Data, Size, *pos);
    // Advance pos by 1 to consume the length byte if we used it.
    // But be conservative: if remaining==1, we still create 0-length string.
    if (remaining > 1) {
        (*pos)++;
        size_t use = (size_t)(requested % (len));
        if (use == 0) use = 1; // ensure at least 1
        if (use > remaining - 1) use = remaining - 1;
        xmlChar *ret = xmlStrndup((const xmlChar *)(Data + *pos), (int)use);
        *pos += use;
        return ret;
    } else {
        // fallback: use entire remaining bytes
        xmlChar *ret = xmlStrndup((const xmlChar *)(Data + *pos), (int)len);
        *pos += len;
        return ret;
    }
}

// The fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        // Initialize libxml once.
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0) return 0;

    // We'll create a small graph (chain) of xmlRelaxNGDefine nodes
    // using the fuzz input. Keep the number of nodes small to avoid
    // deep recursions in the target function.
    size_t pos = 0;
    unsigned char n_nodes_byte = read_byte(Data, Size, pos++);
    int n_nodes = 1 + (n_nodes_byte % 3); // 1..3 nodes

    // xmlRelaxNGDefine and xmlRelaxNGDefinePtr are defined in relaxng.c that
    // we included above.
    xmlRelaxNGDefinePtr nodes[4] = {0};
    memset(nodes, 0, sizeof(nodes));

    for (int i = 0; i < n_nodes; i++) {
        // allocate struct using malloc (we will free with free)
        xmlRelaxNGDefinePtr d = (xmlRelaxNGDefinePtr)malloc(sizeof(xmlRelaxNGDefine));
        if (d == NULL) {
            // allocation failed; free already allocated nodes and return
            for (int j = 0; j < i; j++) {
                if (nodes[j]) {
                    if (nodes[j]->name) xmlFree(nodes[j]->name);
                    if (nodes[j]->ns) xmlFree(nodes[j]->ns);
                    if (nodes[j]->value) xmlFree(nodes[j]->value);
                    free(nodes[j]);
                }
            }
            return 0;
        }
        // zero it
        memset(d, 0, sizeof(*d));

        // Fill simple scalar fields from Data (safe reading)
        unsigned char t = read_byte(Data, Size, pos++);
        d->type = (int)(t % 25); // use a bounded range of types

        // node pointer: keep NULL (safer)
        d->node = NULL;

        // depth from next byte (signed-ish)
        unsigned char depth_b = read_byte(Data, Size, pos++);
        d->depth = (short)((int)depth_b - 100);

        // dflags: use next byte bits
        unsigned char flags_b = read_byte(Data, Size, pos++);
        d->dflags = (short)flags_b;

        // Build small strings for name, ns, value using helper
        d->name = dup_xmlchar_from_input(Data, Size, &pos, 16);
        d->ns = dup_xmlchar_from_input(Data, Size, &pos, 16);
        d->value = dup_xmlchar_from_input(Data, Size, &pos, 32);

        // Other pointers left NULL by default (content etc.)
        d->content = NULL;
        d->parent = NULL;
        d->next = NULL;
        d->attrs = NULL;
        d->nameClass = NULL;
        d->nextHash = NULL;
        d->data = NULL;
        d->contModel = NULL;

        nodes[i] = d;
    }

    // Link content pointers based on next byte(s).
    // We'll create simple chains to avoid complicated graphs.
    for (int i = 0; i < n_nodes - 1; i++) {
        unsigned char link_decider = read_byte(Data, Size, pos++);
        if (link_decider & 1) {
            nodes[i]->content = nodes[i + 1];
            nodes[i + 1]->parent = nodes[i];
        }
        if (link_decider & 2) {
            nodes[i]->next = nodes[i + 1];
        }
    }

    // Choose which node to pass to the function:
    unsigned char entry_sel = read_byte(Data, Size, pos++);
    int entry_idx = entry_sel % n_nodes;
    xmlRelaxNGDefinePtr entry = nodes[entry_idx];

    // Call the real target function from relaxng.c that we included above.
    // It may be static in the original file; including relaxng.c makes it
    // available in this translation unit.
    (void)xmlRelaxNGIsCompilable(entry);

    // Free allocations created above.
    for (int i = 0; i < n_nodes; i++) {
        if (nodes[i]) {
            if (nodes[i]->name) xmlFree(nodes[i]->name);
            if (nodes[i]->ns) xmlFree(nodes[i]->ns);
            if (nodes[i]->value) xmlFree(nodes[i]->value);
            free(nodes[i]);
        }
    }

    // Do not call xmlCleanupParser() here; it's global and expensive to re-run
    // on each fuzz input. The fuzzer process will be torn down by the fuzzing
    // harness when done.

    return 0;
}
