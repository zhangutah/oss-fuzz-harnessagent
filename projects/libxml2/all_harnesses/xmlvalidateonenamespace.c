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
// // int
// //xmlValidateElement(xmlValidCtxt *ctxt, xmlDoc *doc, xmlNode *root) {
// //    xmlNodePtr elem;
// //    xmlAttrPtr attr;
// //    xmlNsPtr ns;
// //    xmlChar *value;
// //    int ret = 1;
// //
// //    if (root == NULL) return(0);
// //
// //    CHECK_DTD;
// //
// //    elem = root;
// //    while (1) {
// //        ret &= xmlValidateOneElement(ctxt, doc, elem);
// //
// //        if (elem->type == XML_ELEMENT_NODE) {
// //            attr = elem->properties;
// //            while (attr != NULL) {
// //                if (attr->children == NULL)
// //                    value = xmlStrdup(BAD_CAST "");
// //                else
// //                    value = xmlNodeListGetString(doc, attr->children, 0);
// //                if (value == NULL) {
// //                    xmlVErrMemory(ctxt);
// //                    ret = 0;
// //                } else {
// //                    ret &= xmlValidateOneAttribute(ctxt, doc, elem, attr, value);
// //                    xmlFree(value);
// //                }
// //                attr= attr->next;
// //            }
// //
// //            ns = elem->nsDef;
// //            while (ns != NULL) {
// //                if (elem->ns == NULL)
// //                    ret &= xmlValidateOneNamespace(ctxt, doc, elem, NULL,
// //                                                   ns, ns->href);
// //                else
// //                    ret &= xmlValidateOneNamespace(ctxt, doc, elem,
// //                                                   elem->ns->prefix, ns,
// //                                                   ns->href);
// //                ns = ns->next;
// //            }
// //
// //            if (elem->children != NULL) {
// //                elem = elem->children;
// //                continue;
// //            }
// //        }
// //
// //        while (1) {
// //            if (elem == root)
// //                goto done;
// //            if (elem->next != NULL)
// //                break;
// //            elem = elem->parent;
// //        }
// //        elem = elem->next;
// //    }
// //
// //done:
// //    return(ret);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlValidateOneNamespace(xmlValidCtxt * ctxt, xmlDoc * doc, xmlNode * elem, const xmlChar * prefix, xmlNs * ns, const xmlChar * value);
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

/* Use project-relative absolute includes discovered in the workspace */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/valid.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzzer entry point required by libFuzzer/LLVMFuzzer:
 extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Make a NUL-terminated copy of the input for safe string ops */
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /*
     * Try to parse the input as an XML document. If parsing fails,
     * create a minimal document with a root element so we can still
     * exercise xmlValidateOneNamespace.
     */
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    xmlNodePtr root = NULL;
    if (doc) root = xmlDocGetRootElement(doc);

    if (!doc) {
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (!doc) {
            free(buf);
            return 0;
        }
        root = xmlNewNode(NULL, BAD_CAST "root");
        xmlDocSetRootElement(doc, root);
    } else if (!root) {
        root = xmlNewNode(NULL, BAD_CAST "root");
        xmlDocSetRootElement(doc, root);
    }

    /* Build prefix, href and value payloads from the input bytes (if available) */
    size_t pos = 0;
    xmlChar *prefix_str = NULL;
    const xmlChar *prefix_arg = NULL;
    xmlChar *href = NULL;
    xmlChar *value = NULL;

    if (Size >= 2) {
        /* Use first byte as a small length selector for prefix */
        pos = 1;
        size_t pref_len = (size_t)(Data[0] % 8); /* small prefix 0..7 */
        if (pref_len > 0 && pos + pref_len <= Size) {
            prefix_str = xmlStrndup((const xmlChar *)(buf + pos), pref_len);
            prefix_arg = prefix_str;
            pos += pref_len;
        }
    }

    /* Build href from subsequent bytes, cap length to avoid huge allocations */
    if (pos < Size) {
        size_t avail = Size - pos;
        size_t n = avail > 128 ? 128 : avail;
        href = xmlStrndup((const xmlChar *)(buf + pos), n);
        pos += n;
    }

    /* Ensure we have a non-empty href as xmlValidateOneNamespace requires ns->href != NULL */
    if (href == NULL || xmlStrlen(href) == 0) {
        if (href) xmlFree(href);
        href = xmlStrdup(BAD_CAST "http://example.invalid/");
    }

    /* Build value from remaining bytes, cap its length too */
    if (pos < Size) {
        size_t avail = Size - pos;
        size_t n = avail > 512 ? 512 : avail;
        value = xmlStrndup((const xmlChar *)(buf + pos), n);
    }
    if (value == NULL) value = xmlStrdup(BAD_CAST "");

    /*
     * Create a namespace attached to the root element.
     * xmlNewNs attaches the namespace to the node and will be cleaned up
     * when the document is freed.
     */
    xmlNsPtr ns = xmlNewNs(root, href, prefix_arg ? prefix_arg : NULL);

    /*
     * Create a validation context. Prefer creating a real context rather
     * than passing NULL to avoid potential internal dereferences.
     */
    xmlValidCtxtPtr vctxt = xmlNewValidCtxt();
    if (vctxt) {
        /* suppress potential noisy messages from the library during fuzzing */
        vctxt->error = NULL;
        vctxt->warning = NULL;
    }

    /*
     * Call the target function. For prefix parameter, pass either the
     * constructed prefix or NULL (if none was constructed).
     *
     * Ensure elem and ns->href are non-NULL (we made sure above).
     */
    xmlValidateOneNamespace(vctxt, doc, root,
                            prefix_arg ? prefix_arg : NULL,
                            ns,
                            (const xmlChar *)value);

    /* Clean up allocations and libxml2 state */
    if (vctxt) xmlFreeValidCtxt(vctxt);
    if (prefix_str) xmlFree(prefix_str);
    if (href) xmlFree(href);
    if (value) xmlFree(value);

    if (doc) xmlFreeDoc(doc);
    xmlCleanupParser();

    free(buf);
    return 0;
}
