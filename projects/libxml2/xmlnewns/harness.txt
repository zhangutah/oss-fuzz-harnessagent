// Generate a fuzz driver based the given function signature in C language. Output the full driver code in reply.
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// // Example 1:
// 
// // static xmlNsPtr
// //xmlDOMWrapStoreNs(xmlDocPtr doc,
// //		   const xmlChar *nsName,
// //		   const xmlChar *prefix)
// //{
// //    xmlNsPtr ns;
// //
// //    if (doc == NULL)
// //	return (NULL);
// //    ns = xmlTreeEnsureXMLDecl(doc);
// //    if (ns == NULL)
// //	return (NULL);
// //    if (ns->next != NULL) {
// //	/* Reuse. */
// //	ns = ns->next;
// //	while (ns != NULL) {
// //	    if (((ns->prefix == prefix) ||
// //		xmlStrEqual(ns->prefix, prefix)) &&
// //		xmlStrEqual(ns->href, nsName)) {
// //		return (ns);
// //	    }
// //	    if (ns->next == NULL)
// //		break;
// //	    ns = ns->next;
// //	}
// //    }
// //    /* Create. */
// //    if (ns != NULL) {
// //        ns->next = xmlNewNs(NULL, nsName, prefix);
// //        return (ns->next);
// //    }
// //    return(NULL);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlNs * xmlNewNs(xmlNode * node, const xmlChar * href, const xmlChar * prefix);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Prefer absolute project header path as provided by analyzer */
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzz driver for:
   xmlNs * xmlNewNs(xmlNode * node, const xmlChar * href, const xmlChar * prefix);

 The fuzzer entry point:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    size_t pos = 0;

    /* Use first byte to decide whether to pass a node (element) or NULL */
    int use_node = Data[pos++] & 1;

    /* Remaining bytes are split into href and prefix strings */
    size_t remain = (pos < Size) ? (Size - pos) : 0;
    size_t href_len = remain / 2;
    size_t prefix_len = remain - href_len;

    const xmlChar *href = NULL;
    const xmlChar *prefix = NULL;
    xmlChar *href_buf = NULL;
    xmlChar *prefix_buf = NULL;

    if (href_len > 0) {
        href_buf = (xmlChar *)malloc(href_len + 1);
        if (href_buf == NULL)
            return 0;
        memcpy(href_buf, Data + pos, href_len);
        href_buf[href_len] = 0;
        href = href_buf;
    }
    pos += href_len;

    if (prefix_len > 0) {
        prefix_buf = (xmlChar *)malloc(prefix_len + 1);
        if (prefix_buf == NULL) {
            free(href_buf);
            return 0;
        }
        memcpy(prefix_buf, Data + pos, prefix_len);
        prefix_buf[prefix_len] = 0;
        prefix = prefix_buf;
    }

    xmlNs *ns = NULL;

    if (!use_node) {
        /* Pass NULL node - exercises branch where node==NULL */
        ns = xmlNewNs(NULL, href, prefix);
        if (ns != NULL) {
            /* detach and free just in case */
            xmlFreeNs(ns);
        }
    } else {
        /* Create a stack xmlNode and initialize to zero, then set type to element */
        xmlNode node;
        memset(&node, 0, sizeof(node));
        node.type = XML_ELEMENT_NODE;
        node.nsDef = NULL;
        node.properties = NULL;
        node.next = NULL;
        node.prev = NULL;
        node.parent = NULL;
        node.children = NULL;
        node.name = NULL;

        ns = xmlNewNs(&node, href, prefix);
        if (ns != NULL) {
            /* Detach ns from node->nsDef list to avoid leaving dangling pointers */
            if (node.nsDef == ns) {
                node.nsDef = ns->next;
            } else {
                xmlNs *prev = node.nsDef;
                while (prev != NULL && prev->next != ns)
                    prev = prev->next;
                if (prev != NULL)
                    prev->next = ns->next;
            }
            /* clear next to be safe */
            ns->next = NULL;
            xmlFreeNs(ns);
        }
        /* Note: node is on stack, no further cleanup required */
    }

    free(href_buf);
    free(prefix_buf);

    return 0;
}
