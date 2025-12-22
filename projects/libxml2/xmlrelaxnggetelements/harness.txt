#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the public Relax-NG header (guards prevent double-define) */
#include "/src/libxml2/include/libxml/relaxng.h"

/* Include the implementation to access the static function directly.
 * This makes the static xmlRelaxNGGetElements visible in this TU.
 */
#include "/src/libxml2/relaxng.c"

/* Fuzzer entry point expected by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Limit complexity to avoid extremely large allocations from fuzz input */
    const size_t MAX_NODES = 64;
    size_t n = (Size > 1) ? (Size / 2) : 1;
    if (n == 0) n = 1;
    if (n > MAX_NODES) n = MAX_NODES;

    /* Create a parser context and initialize it */
    xmlRelaxNGParserCtxtPtr ctxt = (xmlRelaxNGParserCtxtPtr)xmlMalloc(sizeof(*ctxt));
    if (ctxt == NULL)
        return 0;
    memset(ctxt, 0, sizeof(*ctxt));
    /* Ensure no parse errors (the function returns early if nbErrors != 0) */
    ctxt->nbErrors = 0;
    /* Store buffer/size for possible later usage in code paths */
    ctxt->buffer = (const char *)Data;
    ctxt->size = (int)Size;

    /* Build an array of xmlRelaxNGDefine nodes derived from the input bytes.
     * We allocate definitions with xmlMalloc so they are freed with xmlFree.
     */
    xmlRelaxNGDefinePtr *nodes = (xmlRelaxNGDefinePtr *)xmlMalloc(n * sizeof(xmlRelaxNGDefinePtr));
    if (nodes == NULL) {
        xmlFree(ctxt);
        return 0;
    }
    memset(nodes, 0, n * sizeof(xmlRelaxNGDefinePtr));

    for (size_t i = 0; i < n; i++) {
        xmlRelaxNGDefinePtr nd = (xmlRelaxNGDefinePtr)xmlMalloc(sizeof(struct _xmlRelaxNGDefine));
        if (nd == NULL) {
            /* cleanup partial allocations */
            for (size_t j = 0; j < i; j++) xmlFree(nodes[j]);
            xmlFree(nodes);
            xmlFree(ctxt);
            return 0;
        }
        /* initialize fields */
        memset(nd, 0, sizeof(struct _xmlRelaxNGDefine));

        /* Derive a type value from input; ensure it's within the enum bounds.
         * Using modulo with a safe upper bound (XML_RELAXNG_START has the last enum)
         */
        int byte = Data[i % Size];
        int type_range = XML_RELAXNG_START + 1; /* enum max + 1 */
        if (type_range <= 0) type_range = 1;
        nd->type = (xmlRelaxNGType)(byte % type_range);

        /* fill other pointers/strings with NULL; content/next/parent updated later */
        nd->node = NULL;
        nd->name = NULL;
        nd->ns = NULL;
        nd->value = NULL;
        nd->data = NULL;
        nd->content = NULL;
        nd->parent = NULL;
        nd->next = NULL;
        nd->attrs = NULL;
        nd->nameClass = NULL;
        nd->nextHash = NULL;
        nd->depth = 0;
        nd->dflags = 0;
        nd->contModel = NULL;

        nodes[i] = nd;
    }

    /* NOTE: Do NOT link nodes into a long top-level next chain.
     * Long next chains combined with content pointers derived from fuzzed data
     * can create traversal paths that are extremely long or cyclic for the
     * xmlRelaxNGGetElements traversal. Keep next pointers NULL to ensure
     * traversal remains bounded.
     *
     * (All next pointers are already zeroed by memset above.)
     */

    /* Use input to create some content chains:
     * For each node where the corresponding byte has a particular bit set,
     * point content to the next node (if any). Ensure that the pointed-to
     * node's next remains NULL to keep the sublist short and bounded.
     */
    for (size_t i = 0; i < n; i++) {
        int b = Data[i % Size];
        if (b & 0x1) {
            /* Make the content point to the node after next (if any),
             * or to the immediate next. Keep the target node's next NULL
             * so traversal of that sublist is short.
             */
            if (i + 2 < n) {
                nodes[i]->content = nodes[i + 2];
                nodes[i + 2]->next = NULL;
            } else if (i + 1 < n) {
                nodes[i]->content = nodes[i + 1];
                nodes[i + 1]->next = NULL;
            } else {
                nodes[i]->content = NULL;
            }
            /* parent pointers will be set by xmlRelaxNGGetElements when descending */
        } else {
            nodes[i]->content = NULL;
        }
    }

    /* Derive eora (element/attribute/data-or-any etc.) from the first byte */
    int eora = Data[0] % 3; /* 0,1,2 acceptable values for the function */

    /* Call the target function with constructed context and definition list.
     * We pass the head of the list (nodes[0]) as def.
     */
    xmlRelaxNGDefinePtr *result = xmlRelaxNGGetElements(ctxt, nodes[0], eora);

    /* Free returned array if any (allocated with xmlMalloc/xmlRealloc in the
     * implementation). Individual xmlRelaxNGDefinePtr elements are not owned
     * by that array, so we only free the array itself.
     */
    if (result != NULL) {
        xmlFree(result);
    }

    /* Cleanup nodes and context */
    for (size_t i = 0; i < n; i++) {
        xmlFree(nodes[i]);
    }
    xmlFree(nodes);

    /* free additional fields in ctxt if any were allocated (none here) */
    xmlFree(ctxt);

    return 0;
}
