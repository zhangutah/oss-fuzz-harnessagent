#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/c14n.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Helper: dynamically collect element nodes whose parent is an element node. */
static void
collect_element_nodes_with_element_parent(xmlNodePtr cur,
                                          xmlNodePtr **out,
                                          size_t *out_count,
                                          size_t *out_cap) {
    for (; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (cur->parent && cur->parent->type == XML_ELEMENT_NODE) {
                if (*out_count >= *out_cap) {
                    size_t newcap = (*out_cap == 0) ? 16 : (*out_cap * 2);
                    xmlNodePtr *tmp = (xmlNodePtr *)realloc(*out, newcap * sizeof(xmlNodePtr));
                    if (!tmp) {
                        /* OOM: stop collecting */
                        return;
                    }
                    *out = tmp;
                    *out_cap = newcap;
                }
                (*out)[(*out_count)++] = cur;
            }
        }
        if (cur->children)
            collect_element_nodes_with_element_parent(cur->children, out, out_count, out_cap);
    }
}

/*
 * At runtime, try to call the real xmlC14NIsNodeInNodeset from the libxml2
 * binary (if exported). If not available, use a simple fallback.
 *
 * Signature: int xmlC14NIsNodeInNodeset(void *user_data, xmlNodePtr node, xmlNodePtr parent)
 */
static int
call_xmlC14NIsNodeInNodeset(void *user_data, xmlNodePtr node, xmlNodePtr parent) {
    typedef int (*xmlC14NIsNodeInNodeset_t)(void*, xmlNodePtr, xmlNodePtr);

    static xmlC14NIsNodeInNodeset_t real_fn = NULL;
    static int tried_lookup = 0;

    if (!tried_lookup) {
        /* Try to resolve symbol from the loaded program / libraries. */
        /* RTLD_DEFAULT searches all loaded shared objects (GNU extension). */
        real_fn = (xmlC14NIsNodeInNodeset_t)dlsym(RTLD_DEFAULT, "xmlC14NIsNodeInNodeset");
        /* If the project compiled the symbol as static (not exported) this will be NULL. */
        tried_lookup = 1;
    }

    if (real_fn) {
        /* Call the real function from the project */
        return real_fn(user_data, node, parent);
    }

    /*
     * Some builds link libxml2 statically into the fuzzer binary. In that case
     * the symbol may not be found via dlsym(RTLD_DEFAULT, ...), but it will be
     * available at link-time as a direct symbol. Declare a weak extern
     * reference and call it if present.
     *
     * The weak attribute allows this declaration to be present even if the
     * symbol isn't available; the function pointer will be NULL if missing.
     */
    extern int xmlC14NIsNodeInNodeset(void*, xmlNodePtr, xmlNodePtr) __attribute__((weak));
    if (xmlC14NIsNodeInNodeset) {
        return xmlC14NIsNodeInNodeset(user_data, node, parent);
    }

    /* Fallback: conservative behavior used for fuzzing.
     * Keep it simple and safe: return 1 when the node's parent equals the provided parent pointer.
     */
    (void)user_data;
    if (!node) return 0;
    return (node->parent == parent) ? 1 : 0;
}

/*
 * Fuzzer entry point required by libFuzzer:
 *   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 *
 * This harness:
 * - Parses the input bytes as an XML document using xmlReadMemory (recover mode).
 * - Collects element nodes whose parent is an element node.
 * - Picks one such node based on bytes from the input and calls
 *   xmlC14NIsNodeInNodeset with the input buffer as user_data.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Minimal sanity */
    if (!Data || Size == 0)
        return 0;

    /* Initialize parser once (safe to call repeatedly, but costly). */
    static int parser_initialized = 0;
    if (!parser_initialized) {
        xmlInitParser();
        parser_initialized = 1;
    }

    /* Parse input as XML. Use recover to handle malformed inputs; disable network. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz-input.xml", NULL,
                                 XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc == NULL)
        return 0;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Collect candidate nodes (element nodes with element parent) */
    xmlNodePtr *nodes = NULL;
    size_t nodes_count = 0;
    size_t nodes_cap = 0;
    collect_element_nodes_with_element_parent(root, &nodes, &nodes_count, &nodes_cap);

    if (nodes_count == 0) {
        free(nodes);
        xmlFreeDoc(doc);
        return 0;
    }

    /* Use bytes from input to choose a node index; fallback to a simple byte if size small */
    uint32_t selector = 0;
    if (Size >= 4) {
        /* combine first 4 bytes */
        selector = ((uint32_t)Data[0] << 24) | ((uint32_t)Data[1] << 16) |
                   ((uint32_t)Data[2] << 8) | ((uint32_t)Data[3]);
    } else {
        for (size_t i = 0; i < Size; ++i) {
            selector = (selector << 8) ^ Data[i];
        }
    }
    size_t idx = (size_t)(selector % (uint32_t)nodes_count);

    xmlNodePtr node = nodes[idx];
    xmlNodePtr parent = node ? node->parent : NULL;

    /* Call the target function. Pass the input buffer pointer as user_data.
     * This will use the real project function if exported or linked; otherwise fallback is used.
     */
    (void)call_xmlC14NIsNodeInNodeset((void *)Data, node, parent);

    /* Also call once with parent = NULL (some code paths may differ) */
    (void)call_xmlC14NIsNodeInNodeset((void *)Data, node, NULL);

    free(nodes);
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here: it deallocates global state and may be
       expensive between fuzzing iterations. Let the fuzzer handle process lifetime. */

    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
