// Fixed fuzz driver for: void xmlFreeNode(xmlNode * cur);
// Entry point: LLVMFuzzerTestOneInput
//
// Changes made to fix memory leaks reported by LeakSanitizer:
// - Avoid allocating cur->content for node types where xmlFreeNode does not free it
//   (notably XML_ELEMENT_NODE and XML_ENTITY_REF_NODE).
// - Avoid allocating cur->name for text/comment nodes (they use a static name value).
// - Remove XML_ENTITY_REF_NODE from the selectable safe types to avoid creating children
//   that xmlFreeNode won't free.
// These changes ensure all xmlStrndup/xmlMalloc allocations are freed by xmlFreeNode.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Prefer the absolute project header path as requested. */
#include "/src/libxml2/include/libxml/tree.h"
/* xmlStringText is declared in parserInternals.h */ 
#include "/src/libxml2/include/libxml/parserInternals.h"

/* Helper: clamp a size to a max to avoid excessive allocations. */
static size_t clamp_size(size_t v, size_t max) {
    return (v > max) ? max : v;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Safe node types that share the xmlNode layout.
     * Note: XML_ENTITY_REF_NODE is omitted because xmlFreeNode does not free
     * children/content the same way and that may cause leaks if children are created.
     */
    const xmlElementType safe_types[] = {
        XML_ELEMENT_NODE,
        XML_TEXT_NODE,
        XML_CDATA_SECTION_NODE,
        /* XML_ENTITY_REF_NODE, */ /* removed to avoid special-case behavior */
        XML_PI_NODE,
        XML_COMMENT_NODE,
        XML_DOCUMENT_FRAG_NODE,
        XML_XINCLUDE_START,
        XML_XINCLUDE_END
    };
    const size_t n_types = sizeof(safe_types) / sizeof(safe_types[0]);

    /* Choose a type based on first byte. */
    uint8_t t = Data[0];
    xmlElementType chosen_type = safe_types[t % n_types];

    /* Allocate main node with libxml2 allocator to match xmlFree usage. */
    xmlNodePtr cur = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
    if (cur == NULL) return 0;
    memset(cur, 0, sizeof(xmlNode));

    cur->type = chosen_type;
    cur->doc = NULL; /* keep NULL so no dictionary handling from a doc */

    /* Use remaining bytes to populate name/content safely. */
    const uint8_t *p = Data + 1;
    size_t remaining = (Size > 1) ? (Size - 1) : 0;

    /* Set name:
     * - For text and comment nodes, the name is a global static (xmlStringText),
     *   allocating a name would not be freed by xmlFreeNode, causing a leak.
     * - For other node types, allocate a name from input bytes.
     */
    if (chosen_type == XML_TEXT_NODE || chosen_type == XML_COMMENT_NODE) {
        cur->name = xmlStringText;
    } else if (remaining > 0) {
        size_t namelen = clamp_size(remaining, 64);
        cur->name = xmlStrndup((const xmlChar *)p, (int)namelen);
        if (remaining > namelen) {
            p += namelen;
            remaining -= namelen;
        } else {
            remaining = 0;
        }
    }

    /* Set content only for node types where xmlFreeNode will free content:
     * text, comment, cdata, and PI nodes.
     * Do NOT set content for ELEMENT_NODE (xmlFreeNode doesn't free element->content)
     * or other types that have special handling.
     */
    if (remaining > 0 &&
        (cur->type == XML_TEXT_NODE ||
         cur->type == XML_COMMENT_NODE ||
         cur->type == XML_CDATA_SECTION_NODE ||
         cur->type == XML_PI_NODE)) {
        size_t content_len = clamp_size(remaining, 128);
        cur->content = xmlStrndup((const xmlChar *)p, (int)content_len);
        if (remaining > content_len) {
            p += content_len;
            remaining -= content_len;
        } else {
            remaining = 0;
        }
    }

    /* Optionally create a single child node if there are bytes left.
     * Only create a child if the parent type will cause xmlFreeNode to free children.
     * (We removed XML_ENTITY_REF_NODE from selectable types to avoid the case where
     * children are not freed.)
     */
    if (remaining > 0) {
        xmlNodePtr child = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
        if (child != NULL) {
            memset(child, 0, sizeof(xmlNode));
            /* Make child a text node to ensure safe layout and predictable freeing. */
            child->type = XML_TEXT_NODE;
            child->doc = NULL;
            /* Name for text node should be the static xmlStringText. */
            child->name = xmlStringText;
            size_t child_len = clamp_size(remaining, 64);
            child->content = xmlStrndup((const xmlChar *)p, (int)child_len);

            /* Link child into cur's children list */
            cur->children = child;
            cur->last = child;
            child->parent = cur;
        }
    }

    /* Ensure properties and nsDef are NULL to avoid calling specialized frees. */
    cur->properties = NULL;
    cur->nsDef = NULL;

    /* Call the target function.
     * xmlFreeNode will recursively free children and strings using xmlFree.
     */
    xmlFreeNode(cur);

    /* After xmlFreeNode, cur and allocated strings/children should be freed. */
    return 0;
}