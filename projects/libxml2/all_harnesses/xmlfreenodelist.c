#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Include the libxml2 tree header (absolute path from workspace) */
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzzer entry point for xmlFreeNodeList(xmlNode *cur)

 This harness builds a small, well-formed in-memory xmlNode list/tree
 from the input bytes and calls xmlFreeNodeList on the constructed root.

 Design choices for safety:
 - We avoid setting types that would dispatch to xmlFreeNsList or xmlFreeDoc by
   constraining node->type to a curated list of safe xmlElementType values.
 - We keep properties and other complex fields NULL so that callbacks
   like xmlFreePropList are not invoked.
 - We set doc=NULL so that dict-related code paths depending on doc->dict
   are skipped.
 - Number of nodes and depth are bounded to small values to avoid OOM.
*/

/* Helper to create a single node with fields zeroed and some fields set.
   Updates pos through the pos_ptr pointer. */
static xmlNodePtr create_node(const uint8_t *Data, size_t Size, size_t *pos_ptr) {
    xmlNodePtr n = (xmlNodePtr)malloc(sizeof(struct _xmlNode));
    if (n == NULL) return NULL;
    /* Zero whole struct so fields like properties/nsDef/etc are NULL */
    memset(n, 0, sizeof(struct _xmlNode));

    /* make sure _private is NULL for clarity */
    n->_private = NULL;

    size_t pos = *pos_ptr;

    /* Map input into a curated list of safe node types.
       Exclude types that would cause xmlFreeDoc or xmlFreeNsList:
         - XML_DOCUMENT_NODE (9) (would call xmlFreeDoc)
         - XML_HTML_DOCUMENT_NODE (13) (would call xmlFreeDoc)
         - XML_NAMESPACE_DECL (18) (has different layout and would call xmlFreeNsList)
       Also exclude entity/notation-like nodes that have special freeing
       semantics. Choose types that are safe to represent with struct _xmlNode allocation. */
    const int safe_types[] = {
        XML_ELEMENT_NODE,       /* 1 */
        XML_TEXT_NODE,          /* 3 */
        XML_CDATA_SECTION_NODE, /* 4 */
        XML_PI_NODE,            /* 7 */
        XML_COMMENT_NODE        /* 8 */
    };
    const size_t safe_count = sizeof(safe_types) / sizeof(safe_types[0]);

    if (pos < Size) {
        uint8_t t = Data[pos++];
        int mapped = safe_types[t % safe_count];
        n->type = (xmlElementType)mapped;
    } else {
        n->type = XML_ELEMENT_NODE;
    }

    /* Keep name, content, properties NULL to avoid complex frees */
    n->name = NULL;
    n->children = NULL;
    n->last = NULL;
    n->parent = NULL;
    n->next = NULL;
    n->prev = NULL;
    n->doc = NULL; /* keep doc NULL to avoid dict usage */
    n->ns = NULL;
    n->content = NULL;
    /* properties and nsDef are zeroed by memset */

    *pos_ptr = pos;
    return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    size_t pos = 0;

    /* Determine how many sibling nodes to create (1..8) */
    size_t max_nodes = 8;
    size_t nodes_count = 1;
    if (pos < Size) {
        nodes_count = 1 + (Data[pos++] % max_nodes);
    }

    /* Cap nodes_count to available size to be conservative */
    if (nodes_count > 64) nodes_count = 64;

    /* allocate an array to keep pointers so we can link easily */
    xmlNodePtr *nodes = (xmlNodePtr *)malloc(sizeof(xmlNodePtr) * nodes_count);
    if (nodes == NULL) return 0;

    /* Create sibling nodes */
    size_t created = 0;
    for (; created < nodes_count; ++created) {
        xmlNodePtr n = create_node(Data, Size, &pos);
        if (n == NULL) break;
        nodes[created] = n;
    }

    if (created == 0) {
        free(nodes);
        return 0;
    }

    /* Link siblings (next/prev) */
    for (size_t i = 0; i + 1 < created; ++i) {
        nodes[i]->next = nodes[i+1];
        nodes[i+1]->prev = nodes[i];
    }

    /* Optionally add a small child to some nodes to exercise child traversal.
       We'll add at most one child per node and limit depth to 2. */
    for (size_t i = 0; i < created && pos < Size; ++i) {
        /* Use next byte bit to decide whether to add a child */
        uint8_t selector = Data[pos++];
        if ((selector & 0x1) == 0) continue;

        /* create a single child node */
        xmlNodePtr child = create_node(Data, Size, &pos);
        if (child == NULL) continue;

        /* attach as first child */
        nodes[i]->children = child;
        nodes[i]->last = child;
        child->parent = nodes[i];

        /* Optionally attach a sibling to that child (making two-level depth) */
        if (pos < Size && (Data[pos++] & 0x1)) {
            xmlNodePtr child2 = create_node(Data, Size, &pos);
            if (child2 != NULL) {
                child->next = child2;
                child2->prev = child;
                child2->parent = nodes[i];
                nodes[i]->last = child2;
            }
        }
    }

    /* Call the target function on the first node (root of our list) */
    /* This is the function being fuzzed. */
    xmlNodePtr root = nodes[0];
    xmlFreeNodeList(root);

    /*
     xmlFreeNodeList is expected to free the nodes and attached content.
     To avoid double-free we now clear our references in the nodes[] array
     (ownership of those node pointers was transferred to xmlFreeNodeList).
     */
    for (size_t i = 0; i < created; ++i) {
        nodes[i] = NULL;
    }

    free(nodes);

    return 0;
}
