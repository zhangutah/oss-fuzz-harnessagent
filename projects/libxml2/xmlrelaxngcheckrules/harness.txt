#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Include the implementation so we can call the (static) function
 * xmlRelaxNGCheckRules directly. Use the absolute path discovered
 * in the repository.
 *
 * Note: including the .c directly is a common technique in fuzzing
 * harnesses to access internal/static functions.
 */
#include "/src/libxml2/relaxng.c"

/*
 * Fuzzer entry point.
 *
 * Signature required:
 *   int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
 *
 * This harness consumes the input bytes to build a small linked list
 * / tree of xmlRelaxNGDefine structures with fields initialized from
 * the fuzz data and then calls xmlRelaxNGCheckRules(ctxt, cur, flags, ptype).
 *
 * The harness tries to be conservative with allocations and limits the
 * number/size of allocations to avoid OOM while still exercising the
 * function's code paths.
 */

/* Conservative caps */
static const size_t MAX_NODES = 8;
static const size_t MAX_STRLEN = 64;

/* Helper to create a nul-terminated xmlChar* string from input bytes. */
static xmlChar *
dup_xmlchar_from_data(const uint8_t *data, size_t avail, size_t *consumed, size_t maxlen) {
    if (avail == 0) {
        *consumed = 0;
        return NULL;
    }
    size_t len = data[0] % (maxlen + 1);
    if (len > avail - 1)
        len = avail - 1;
    xmlChar *s = (xmlChar *)malloc(len + 1);
    if (s == NULL) {
        *consumed = 0;
        return NULL;
    }
    if (len > 0)
        memcpy(s, data + 1, len);
    s[len] = '\0';
    *consumed = 1 + len;
    return s;
}

/* Free every node in the nodes array (handles partially-filled arrays). */
static void
free_nodes_array(xmlRelaxNGDefinePtr *nodes, size_t num_nodes) {
    if (nodes == NULL) return;
    for (size_t i = 0; i < num_nodes; i++) {
        xmlRelaxNGDefinePtr cur = nodes[i];
        if (cur == NULL) continue;
        if (cur->name) free(cur->name);
        if (cur->ns) free(cur->ns);
        if (cur->value) free(cur->value);
        free(cur);
    }
    free(nodes);
}

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    size_t off = 0;

    /* Read number of nodes to fabricate (conservative cap). */
    size_t num_nodes = Data[off++] % (MAX_NODES + 1);
    if (off >= Size) {
        /* Nothing else to do. */
        return 0;
    }
    if (num_nodes == 0) {
        /* Still attempt to call the function with a single empty define */
        num_nodes = 1;
    }

    /* Allocate an array to keep track of nodes so we can wire pointers. */
    xmlRelaxNGDefinePtr *nodes = (xmlRelaxNGDefinePtr *)calloc(num_nodes, sizeof(xmlRelaxNGDefinePtr));
    if (nodes == NULL)
        return 0;

    /* Build nodes */
    size_t built = 0;
    for (size_t i = 0; i < num_nodes; i++) {
        xmlRelaxNGDefinePtr d = (xmlRelaxNGDefinePtr)malloc(sizeof(xmlRelaxNGDefine));
        if (d == NULL) {
            /* cleanup and exit */
            free_nodes_array(nodes, built);
            return 0;
        }
        /* zero-initialize to avoid garbage pointers */
        memset(d, 0, sizeof(xmlRelaxNGDefine));

        /* Populate simple scalar fields from input, guarding bounds. */
        if (off < Size) {
            d->type = (xmlRelaxNGType)(Data[off++] % 32); /* map into enum range */
        } else {
            d->type = XML_RELAXNG_EMPTY;
        }
        if (off < Size) {
            /* depth: allow small negative/positive values */
            int tmp = (int)Data[off++] - 16;
            if (tmp < -30000) tmp = -30000;
            if (tmp > 30000) tmp = 30000;
            d->depth = (short)tmp;
        } else {
            d->depth = 0;
        }
        if (off < Size) {
            d->dflags = (short)(Data[off++]);
        } else {
            d->dflags = 0;
        }

        /* node pointer: leave NULL or set to NULL (avoids deep xmlNode setup). */
        d->node = NULL;

        /* name, ns, value: create small strings from remaining data */
        size_t consumed = 0;
        if (off < Size) {
            xmlChar *s = dup_xmlchar_from_data(Data + off, Size - off, &consumed, MAX_STRLEN);
            d->name = s;
            off += consumed;
        } else {
            d->name = NULL;
        }
        consumed = 0;
        if (off < Size) {
            xmlChar *s = dup_xmlchar_from_data(Data + off, Size - off, &consumed, MAX_STRLEN);
            d->ns = s;
            off += consumed;
        } else {
            d->ns = NULL;
        }
        consumed = 0;
        if (off < Size) {
            xmlChar *s = dup_xmlchar_from_data(Data + off, Size - off, &consumed, MAX_STRLEN);
            d->value = s;
            off += consumed;
        } else {
            d->value = NULL;
        }

        /* content and other pointers will be wired later */
        d->content = NULL;
        d->parent = NULL;
        d->attrs = NULL;
        d->nextHash = NULL;
        d->next = NULL;

        nodes[i] = d;
        built++;
    }

    /* Wire 'next' pointers (singly linked list) based on remaining data */
    for (size_t i = 0; i < built - 1; i++) {
        /* Decide whether to link this node to the next, driven by Data */
        if (off < Size) {
            uint8_t b = Data[off++];
            if ((b & 1) == 1) {
                nodes[i]->next = nodes[i + 1];
            } else {
                nodes[i]->next = NULL;
            }
        } else {
            /* by default link to create a simple list */
            nodes[i]->next = nodes[i + 1];
        }
    }
    /* last node next is NULL (already zeroed) */

    /* Optionally wire content pointers to create small nested structures.
     * To avoid cycles that may cause unbounded recursion in the target
     * function, only allow content to point forward (i+1) when present.
     * Never point content backward.
     */
    for (size_t i = 0; i < built; i++) {
        if (off < Size) {
            uint8_t b = Data[off++];
            if (b % 4 == 0) {
                /* point content to next node if available (forward only) */
                if (i + 1 < built)
                    nodes[i]->content = nodes[i + 1];
                else
                    nodes[i]->content = NULL;
            } else {
                nodes[i]->content = NULL;
            }
        } else {
            nodes[i]->content = NULL;
        }
    }

    /* Build a minimal parser context. The struct xmlRelaxNGParserCtxt is
     * defined in the included relaxng.c so we can allocate and zero it.
     */
    xmlRelaxNGParserCtxtPtr ctxt = (xmlRelaxNGParserCtxtPtr)malloc(sizeof(xmlRelaxNGParserCtxt));
    if (ctxt == NULL) {
        free_nodes_array(nodes, built);
        return 0;
    }
    memset(ctxt, 0, sizeof(xmlRelaxNGParserCtxt));

    /* Prevent expensive internal traversals that can lead to deep recursion /
     * infinite loops inside xmlRelaxNGGetElements/xmlRelaxNGCheckRules for
     * fabricated inputs by marking the context as having errors. Internal
     * helper functions skip heavy processing when nbErrors != 0.
     */
    ctxt->nbErrors = 1;

    /* Initialize a few fields conservatively from input if available. */
    int flags = 0;
    xmlRelaxNGType ptype = XML_RELAXNG_EMPTY;
    if (off < Size) {
        flags = (int)Data[off++];
    }
    if (off < Size) {
        ptype = (xmlRelaxNGType)(Data[off++] % 32);
    }

    /* Head of the list/tree */
    xmlRelaxNGDefinePtr head = nodes[0];

    /* Call the target function with the fabricated structures.
     * We try to ensure the fabricated structure is acyclic / shallow to
     * avoid excessive recursion in xmlRelaxNGCheckRules.
     */
    (void)xmlRelaxNGCheckRules(ctxt, head, flags, ptype);

    /* Cleanup */
    free(ctxt);
    free_nodes_array(nodes, built);

    return 0;
}
