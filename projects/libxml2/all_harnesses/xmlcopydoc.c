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
// // xmlNode *
// //xmlStaticCopyNode(xmlNode *node, xmlDoc *doc, xmlNode *parent,
// //                  int extended) {
// //    xmlNodePtr ret;
// //
// //    if (node == NULL) return(NULL);
// //    switch (node->type) {
// //        case XML_TEXT_NODE:
// //        case XML_CDATA_SECTION_NODE:
// //        case XML_ELEMENT_NODE:
// //        case XML_DOCUMENT_FRAG_NODE:
// //        case XML_ENTITY_REF_NODE:
// //        case XML_PI_NODE:
// //        case XML_COMMENT_NODE:
// //        case XML_XINCLUDE_START:
// //        case XML_XINCLUDE_END:
// //	    break;
// //        case XML_ATTRIBUTE_NODE:
// //		return((xmlNodePtr) xmlCopyPropInternal(doc, parent, (xmlAttrPtr) node));
// //        case XML_NAMESPACE_DECL:
// //	    return((xmlNodePtr) xmlCopyNamespaceList((xmlNsPtr) node));
// //
// //        case XML_DOCUMENT_NODE:
// //        case XML_HTML_DOCUMENT_NODE:
// //	    return((xmlNodePtr) xmlCopyDoc((xmlDocPtr) node, extended));
// //        default:
// //            return(NULL);
// //    }
// //
// //    /*
// //     * Allocate a new node and fill the fields.
// //     */
// //    ret = (xmlNodePtr) xmlMalloc(sizeof(xmlNode));
// //    if (ret == NULL)
// //	return(NULL);
// //    memset(ret, 0, sizeof(xmlNode));
// //    ret->type = node->type;
// //
// //    ret->doc = doc;
// //    ret->parent = parent;
// //    if (node->name == xmlStringText)
// //	ret->name = xmlStringText;
// //    else if (node->name == xmlStringTextNoenc)
// //	ret->name = xmlStringTextNoenc;
// //    else if (node->name == xmlStringComment)
// //	ret->name = xmlStringComment;
// //    else if (node->name != NULL) {
// //        if ((doc != NULL) && (doc->dict != NULL))
// //	    ret->name = xmlDictLookup(doc->dict, node->name, -1);
// //	else
// //	    ret->name = xmlStrdup(node->name);
// //        if (ret->name == NULL)
// //            goto error;
// //    }
// //    if ((node->type != XML_ELEMENT_NODE) &&
// //	(node->content != NULL) &&
// //	(node->type != XML_ENTITY_REF_NODE) &&
// //	(node->type != XML_XINCLUDE_END) &&
// //	(node->type != XML_XINCLUDE_START)) {
// //	ret->content = xmlStrdup(node->content);
// //        if (ret->content == NULL)
// //            goto error;
// //    }else{
// //      if (node->type == XML_ELEMENT_NODE)
// //        ret->line = node->line;
// //    }
// //
// //    if (!extended)
// //	goto out;
// //    if (((node->type == XML_ELEMENT_NODE) ||
// //         (node->type == XML_XINCLUDE_START)) && (node->nsDef != NULL)) {
// //        ret->nsDef = xmlCopyNamespaceList(node->nsDef);
// //        if (ret->nsDef == NULL)
// //            goto error;
// //    }
// //
// //    if ((node->type == XML_ELEMENT_NODE) && (node->ns != NULL)) {
// //        xmlNsPtr ns = NULL;
// //        int res;
// //
// //	res = xmlSearchNsSafe(ret, node->ns->prefix, &ns);
// //        if (res < 0)
// //            goto error;
// //	if (ns == NULL) {
// //	    /*
// //	     * Humm, we are copying an element whose namespace is defined
// //	     * out of the new tree scope. Search it in the original tree
// //	     * and add it at the top of the new tree.
// //             *
// //             * TODO: Searching the original tree seems unnecessary. We
// //             * already have a namespace URI.
// //	     */
// //	    res = xmlSearchNsSafe(node, node->ns->prefix, &ns);
// //            if (res < 0)
// //                goto error;
// //	    if (ns != NULL) {
// //	        xmlNodePtr root = ret;
// //
// //		while (root->parent != NULL) root = root->parent;
// //		ret->ns = xmlNewNs(root, ns->href, ns->prefix);
// //            } else {
// //                ret->ns = xmlNewReconciledNs(ret, node->ns);
// //	    }
// //            if (ret->ns == NULL)
// //                goto error;
// //	} else {
// //	    /*
// //	     * reference the existing namespace definition in our own tree.
// //	     */
// //	    ret->ns = ns;
// //	}
// //    }
// //    if ((node->type == XML_ELEMENT_NODE) && (node->properties != NULL)) {
// //        ret->properties = xmlCopyPropList(ret, node->properties);
// //        if (ret->properties == NULL)
// //            goto error;
// //    }
// //    if (node->type == XML_ENTITY_REF_NODE) {
// //	if ((doc == NULL) || (node->doc != doc)) {
// //	    /*
// //	     * The copied node will go into a separate document, so
// //	     * to avoid dangling references to the ENTITY_DECL node
// //	     * we cannot keep the reference. Try to find it in the
// //	     * target document.
// //	     */
// //	    ret->children = (xmlNodePtr) xmlGetDocEntity(doc, ret->name);
// //	} else {
// //            ret->children = node->children;
// //	}
// //	ret->last = ret->children;
// //    } else if ((node->children != NULL) && (extended != 2)) {
// //        xmlNodePtr cur, insert;
// //
// //        cur = node->children;
// //        insert = ret;
// //        while (cur != NULL) {
// //            xmlNodePtr copy = xmlStaticCopyNode(cur, doc, insert, 2);
// //            if (copy == NULL)
// //                goto error;
// //
// //            /* Check for coalesced text nodes */
// //            if (insert->last != copy) {
// //                if (insert->last == NULL) {
// //                    insert->children = copy;
// //                } else {
// //                    copy->prev = insert->last;
// //                    insert->last->next = copy;
// //                }
// //                insert->last = copy;
// //            }
// //
// //            if ((cur->type != XML_ENTITY_REF_NODE) &&
// //                (cur->children != NULL)) {
// //                cur = cur->children;
// //                insert = copy;
// //                continue;
// //            }
// //
// //            while (1) {
// //                if (cur->next != NULL) {
// //                    cur = cur->next;
// //                    break;
// //                }
// //
// //                cur = cur->parent;
// //                insert = insert->parent;
// //                if (cur == node) {
// //                    cur = NULL;
// //                    break;
// //                }
// //            }
// //        }
// //    }
// //
// //out:
// //    if ((xmlRegisterCallbacks) && (xmlRegisterNodeDefaultValue))
// //	xmlRegisterNodeDefaultValue((xmlNodePtr)ret);
// //    return(ret);
// //
// //error:
// //    xmlFreeNode(ret);
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
//     xmlDoc * xmlCopyDoc(xmlDoc * doc, int recursive);
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

/* libxml2 headers */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/* Ensure libxml parser is initialized once for the fuzzer process */
static void libxml_setup(void) __attribute__((constructor));
static void libxml_setup(void) {
    /* xmlInitParser is safe to call multiple times; call once at startup. */
    xmlInitParser();
}

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Copy input into a nul-terminated buffer for xmlReadMemory */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Parse the input bytes as an XML document.
       Use XML_PARSE_RECOVER to tolerate malformed input and XML_PARSE_NONET
       to disallow network access from entities. */
    int options = XML_PARSE_RECOVER | XML_PARSE_NONET;
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzzed.xml", NULL, options);

    if (doc != NULL) {
        /* Call xmlCopyDoc with non-recursive copy (0) */
        xmlDocPtr copy0 = xmlCopyDoc(doc, 0);
        if (copy0 != NULL) {
            xmlFreeDoc(copy0);
        }

        /* Call xmlCopyDoc with recursive copy (non-zero) */
        xmlDocPtr copy1 = xmlCopyDoc(doc, 1);
        if (copy1 != NULL) {
            xmlFreeDoc(copy1);
        }

        /* Free the parsed original document */
        xmlFreeDoc(doc);
    }

    free(buf);
    return 0;
}