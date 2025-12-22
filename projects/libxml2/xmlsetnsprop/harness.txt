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
// //xmlNodeSetLang(xmlNode *cur, const xmlChar *lang) {
// //    xmlNsPtr ns;
// //    xmlAttrPtr attr;
// //    int res;
// //
// //    if ((cur == NULL) || (cur->type != XML_ELEMENT_NODE))
// //        return(1);
// //
// //    res = xmlSearchNsByHrefSafe(cur, XML_XML_NAMESPACE, &ns);
// //    if (res != 0)
// //        return(res);
// //    attr = xmlSetNsProp(cur, ns, BAD_CAST "lang", lang);
// //    if (attr == NULL)
// //        return(-1);
// //
// //    return(0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlAttr * xmlSetNsProp(xmlNode * node, xmlNs * ns, const xmlChar * name, const xmlChar * value);
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
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 Fuzz driver for:
   xmlAttr * xmlSetNsProp(xmlNode * node, xmlNs * ns, const xmlChar * name, const xmlChar * value);

 Entry point required by libFuzzer:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();

    size_t pos = 0;

    /* First byte: flags (bit0 => create ns, other bits reserved) */
    uint8_t flags = Data[pos++];
    int want_ns = (flags & 0x1);

    size_t remaining = (pos <= Size) ? (Size - pos) : 0;
    if (remaining == 0) {
        /* Nothing else; call with minimal sane inputs */
        xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
        if (doc) {
            xmlNodePtr node = xmlNewDocNode(doc, NULL, (const xmlChar *)"root", NULL);
            if (node) xmlDocSetRootElement(doc, node);
            /* call with empty name/value */
            xmlSetNsProp(node, NULL, (const xmlChar *)"", (const xmlChar *)"");
            xmlFreeDoc(doc);
        }
        xmlCleanupParser();
        return 0;
    }

    /* Split remaining bytes into name and value (roughly half/half). */
    size_t name_len = remaining / 2;
    size_t value_len = remaining - name_len;
    if (name_len > 4096) name_len = 4096;
    if (value_len > 4096) value_len = 4096;

    /* Ensure we don't read past Size */
    if (pos + name_len + value_len > Size) {
        /* adjust if necessary */
        if (pos + name_len > Size) name_len = (Size > pos) ? (Size - pos) : 0;
        value_len = (Size > pos + name_len) ? (Size - pos - name_len) : 0;
    }

    /* Allocate and null-terminate the name and value strings */
    unsigned char *name_buf = (unsigned char *)malloc(name_len + 1);
    unsigned char *value_buf = (unsigned char *)malloc(value_len + 1);
    if (name_buf == NULL || value_buf == NULL) {
        free(name_buf);
        free(value_buf);
        xmlCleanupParser();
        return 0;
    }

    if (name_len > 0) {
        memcpy(name_buf, Data + pos, name_len);
    }
    name_buf[name_len] = '\0';
    pos += name_len;

    if (value_len > 0) {
        memcpy(value_buf, Data + pos, value_len);
    }
    value_buf[value_len] = '\0';
    pos += value_len;

    /* Create a minimal document and an element node to operate on */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL) {
        free(name_buf);
        free(value_buf);
        xmlCleanupParser();
        return 0;
    }

    /* Use a non-empty element name for the node; if name_buf is empty use "root" */
    const xmlChar *elem_name = (name_len > 0) ? (const xmlChar *)name_buf : (const xmlChar *)"root";
    xmlNodePtr node = xmlNewDocNode(doc, NULL, elem_name, NULL);
    if (node == NULL) {
        xmlFreeDoc(doc);
        free(name_buf);
        free(value_buf);
        xmlCleanupParser();
        return 0;
    }
    xmlDocSetRootElement(doc, node);

    /* Optionally create a namespace attached to the node.
       Ensure ns->href is non-NULL (xmlSetNsProp checks that). */
    xmlNsPtr ns = NULL;
    if (want_ns) {
        /* Build a small href and prefix from parts of name/value if possible to vary inputs */
        const char *default_href = "http://fuzz.example/";
        const char *default_prefix = "f";
        /* If name_buf has some bytes, craft a small href using hex of first up to 8 bytes */
        char href_buf[64];
        char prefix_buf[16];
        size_t make_href = 0;
        if (name_len > 0) {
            size_t use = (name_len < 8) ? name_len : 8;
            size_t idx = 0;
            strcpy(href_buf, "http://fuzz/");
            idx = strlen(href_buf);
            for (size_t i = 0; i < use && idx + 2 < sizeof(href_buf) - 1; ++i) {
                unsigned char b = name_buf[i];
                const char hex[] = "0123456789abcdef";
                href_buf[idx++] = hex[(b >> 4) & 0xF];
                href_buf[idx++] = hex[b & 0xF];
            }
            href_buf[idx] = '\0';
            make_href = 1;
        }

        if (value_len > 0) {
            /* prefix from first byte of value */
            size_t pfx_len = (value_len >= 3) ? 3 : value_len;
            size_t pi = 0;
            for (size_t i = 0; i < pfx_len && i < sizeof(prefix_buf)-1; ++i) {
                unsigned char c = value_buf[i];
                /* make ASCII-ish */
                prefix_buf[pi++] = (char)(0x41 + (c % 26));
            }
            prefix_buf[pi] = '\0';
        } else {
            prefix_buf[0] = '\0';
        }

        const xmlChar *href_arg = (make_href ? (const xmlChar *)href_buf : (const xmlChar *)default_href);
        const xmlChar *prefix_arg = (prefix_buf[0] ? (const xmlChar *)prefix_buf : (const xmlChar *)default_prefix);

        /* xmlNewNs attaches the namespace to the node and returns the ns pointer or NULL */
        ns = xmlNewNs(node, href_arg, prefix_arg);
        /* If xmlNewNs returned NULL, ns remains NULL and xmlSetNsProp will be called with NULL */
    }

    /* Call the target function under test.
       Use name_buf as the attribute name (if empty, pass empty string).
       Use value_buf as the attribute value (may be empty). */
    xmlSetNsProp(node, ns, (const xmlChar *)name_buf, (const xmlChar *)value_buf);

    /* Cleanup */
    xmlFreeDoc(doc);

    free(name_buf);
    free(value_buf);

    /* Clean up global parser state (safe to call repeatedly) */
    xmlCleanupParser();

    return 0;
}
