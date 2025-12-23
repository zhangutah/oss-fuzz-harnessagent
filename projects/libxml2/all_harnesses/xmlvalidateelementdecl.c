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
// // void
// //xmlSAX2ElementDecl(void *ctx, const xmlChar * name, int type,
// //            xmlElementContent *content)
// //{
// //    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;
// //    xmlElementPtr elem = NULL;
// //
// //    /* Avoid unused variable warning if features are disabled. */
// //    (void) elem;
// //
// //    if ((ctxt == NULL) || (ctxt->myDoc == NULL))
// //        return;
// //
// //    if (ctxt->inSubset == 1)
// //        elem = xmlAddElementDecl(&ctxt->vctxt, ctxt->myDoc->intSubset,
// //                                 name, (xmlElementTypeVal) type, content);
// //    else if (ctxt->inSubset == 2)
// //        elem = xmlAddElementDecl(&ctxt->vctxt, ctxt->myDoc->extSubset,
// //                                 name, (xmlElementTypeVal) type, content);
// //    else {
// //        xmlFatalErrMsg(ctxt, XML_ERR_INTERNAL_ERROR,
// //	     "SAX.xmlSAX2ElementDecl(%s) called while not in subset\n",
// //	               name, NULL);
// //        return;
// //    }
// //#ifdef LIBXML_VALID_ENABLED
// //    if (elem == NULL)
// //        ctxt->valid = 0;
// //    if (ctxt->validate && ctxt->wellFormed &&
// //        ctxt->myDoc && ctxt->myDoc->intSubset)
// //        ctxt->valid &=
// //            xmlValidateElementDecl(&ctxt->vctxt, ctxt->myDoc, elem);
// //#endif /* LIBXML_VALID_ENABLED */
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlValidateElementDecl(xmlValidCtxt * ctxt, xmlDoc * doc, xmlElement * elem);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmlValidateElementDecl(xmlValidCtxt * ctxt, xmlDoc * doc, xmlElement * elem);
//
// Fuzzer entry point:
//   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Project headers (absolute paths chosen per instructions) */
#include "/src/libxml2/include/libxml/valid.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/* Helper: create a nul-terminated xmlChar* string from input bytes.
 * Consumes up to max_len bytes from *p (with remaining bytes *rem).
 * Returns allocated xmlChar* (caller must free) or NULL on empty.
 */
static xmlChar *
make_xmlstring(const uint8_t **p, size_t *rem, size_t max_len) {
    if (*rem == 0) return NULL;
    size_t take = (*rem < max_len) ? *rem : max_len;
    if (take == 0) return NULL;
    xmlChar *s = (xmlChar *)malloc(take + 1);
    if (!s) return NULL;
    memcpy(s, *p, take);
    s[take] = 0;
    *p += take;
    *rem -= take;
    return s;
}

/* Safe reader for one byte, advancing pointer if available */
static int
read_byte(const uint8_t **p, size_t *rem, uint8_t *out) {
    if (*rem == 0) return 0;
    *out = **p;
    (*p)++;
    (*rem)--;
    return 1;
}

/* Build a small xmlElementContent tree to exercise xmlValidateElementDecl logic.
 * We'll create:
 *   cur -> (OR) with c1 -> ELEMENT (name A/prefix P)
 *                    c2 -> next (OR) where next->c1 -> ELEMENT (may match or differ)
 *
 * This matches code paths that look for duplicate element references.
 */
static xmlElementContent *
build_element_content_duplicate(const uint8_t **p, size_t *rem,
                                xmlChar *name1, xmlChar *prefix1,
                                xmlChar *name2, xmlChar *prefix2) {
    xmlElementContent *cur = (xmlElementContent *)malloc(sizeof(xmlElementContent));
    if (!cur) return NULL;
    memset(cur, 0, sizeof(xmlElementContent));

    xmlElementContent *c1 = (xmlElementContent *)malloc(sizeof(xmlElementContent));
    if (!c1) { free(cur); return NULL; }
    memset(c1, 0, sizeof(xmlElementContent));

    xmlElementContent *next = (xmlElementContent *)malloc(sizeof(xmlElementContent));
    if (!next) { free(cur); free(c1); return NULL; }
    memset(next, 0, sizeof(xmlElementContent));

    xmlElementContent *next_c1 = (xmlElementContent *)malloc(sizeof(xmlElementContent));
    if (!next_c1) { free(cur); free(c1); free(next); return NULL; }
    memset(next_c1, 0, sizeof(xmlElementContent));

    /* Set types */
    cur->type = XML_ELEMENT_CONTENT_OR;
    c1->type = XML_ELEMENT_CONTENT_ELEMENT;
    next->type = XML_ELEMENT_CONTENT_OR;
    next_c1->type = XML_ELEMENT_CONTENT_ELEMENT;

    /* Attach names/prefixes for ELEMENT nodes */
    c1->name = name1;
    c1->prefix = prefix1;
    next_c1->name = name2;
    next_c1->prefix = prefix2;

    /* Link nodes: cur->c1 points to c1 element; cur->c2 -> next; next->c1 -> next_c1 */
    cur->c1 = c1;
    cur->c2 = next;
    next->c1 = next_c1;
    next->c2 = NULL;

    /* Parent pointers (not strictly necessary, but fill in) */
    c1->parent = cur;
    next->parent = cur;
    next_c1->parent = next;

    return cur;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    const uint8_t *p = Data;
    size_t rem = Size;

    /* Prepare xmlValidCtxt */
    xmlValidCtxt *vctxt = (xmlValidCtxt *)calloc(1, sizeof(xmlValidCtxt));
    if (!vctxt) return 0;
    /* Keep callbacks NULL to avoid printing; xmlValidateElementDecl will call xmlErrValidNode
     * which checks ctxt - but having a zeroed ctxt is acceptable for fuzzing. */
    vctxt->valid = 1;

    /* Prepare xmlDoc (minimal) */
    xmlDoc *doc = (xmlDoc *)calloc(1, sizeof(xmlDoc));
    if (!doc) { free(vctxt); return 0; }
    vctxt->doc = doc;

    /* Allocate xmlElement (element declaration) */
    xmlElement *elem = (xmlElement *)calloc(1, sizeof(xmlElement));
    if (!elem) { free(doc); free(vctxt); return 0; }

    /* Choose an element type using one byte */
    uint8_t b = 0;
    if (!read_byte(&p, &rem, &b)) {
        /* if no bytes after header, still call with defaults */
        b = 0;
    }
    /* Map into known enums (0..4 range); prefer MIXED path to reach duplicate checking */
    int pick = b % 5;
    switch (pick) {
        case 0: elem->etype = XML_ELEMENT_TYPE_UNDEFINED; break;
        case 1: elem->etype = XML_ELEMENT_TYPE_EMPTY; break;
        case 2: elem->etype = XML_ELEMENT_TYPE_ANY; break;
        case 3: elem->etype = XML_ELEMENT_TYPE_ELEMENT; break;
        default: elem->etype = XML_ELEMENT_TYPE_MIXED; break;
    }

    /* Build element name from next bytes (cap length) */
    xmlChar *elem_name = make_xmlstring(&p, &rem, 32);
    elem->name = elem_name ? (const xmlChar *)elem_name : (const xmlChar *)"(null)";

    /* If element type is MIXED, craft a content model aiming for duplicate detection */
    if (elem->etype == XML_ELEMENT_TYPE_MIXED) {
        /* Build up to two names/prefixes from remaining data */
        xmlChar *name1 = make_xmlstring(&p, &rem, 24);
        xmlChar *pref1 = make_xmlstring(&p, &rem, 8);
        xmlChar *name2 = make_xmlstring(&p, &rem, 24);
        xmlChar *pref2 = make_xmlstring(&p, &rem, 8);

        /* If any name is missing, default to elem_name or short strings */
        if (!name1) name1 = elem_name ? (xmlChar *)strdup((const char *)elem_name) : (xmlChar *)strdup("A");
        if (!name2) {
            /* To increase chance of duplicates, let name2 equal name1 depending on one byte */
            if (rem > 0 && (*p % 2 == 0)) {
                name2 = (xmlChar *)strdup((const char *)name1);
            } else {
                name2 = (xmlChar *)strdup((const char *)name1);
            }
        }
        if (!pref1) pref1 = (xmlChar *)strdup("");
        if (!pref2) {
            /* sometimes match prefix to trigger logging that prints prefix */
            if (rem > 0 && (*p % 2 == 0)) pref2 = (xmlChar *)strdup((const char *)pref1);
            else pref2 = (xmlChar *)strdup((const char *)pref1);
        }

        xmlElementContent *content = build_element_content_duplicate(&p, &rem, name1, pref1, name2, pref2);
        elem->content = content;
        /* attributes etc left NULL */
    } else {
        elem->content = NULL;
    }

    /* elem->prefix could be set from bytes as well to explore prefix comparisons */
    xmlChar *elem_pref = make_xmlstring(&p, &rem, 8);
    elem->prefix = elem_pref;

    /* Call the function under test */
    /* Note: xmlValidateElementDecl is deprecated but still present in codebase. */
    (void)xmlValidateElementDecl(vctxt, doc, elem);

    /* Cleanup allocated structures:
     * Note: Some xmlElementContent children point to allocated name/prefix strings
     * We free them conservatively.
     */
    if (elem) {
        if (elem->content) {
            xmlElementContent *cur = elem->content;
            /* free c1/name/prefix if allocated separately */
            if (cur->c1) {
                if (cur->c1->name) free((void *)cur->c1->name);
                if (cur->c1->prefix) free((void *)cur->c1->prefix);
                free(cur->c1);
            }
            if (cur->c2) {
                xmlElementContent *next = cur->c2;
                if (next->c1) {
                    if (next->c1->name) free((void *)next->c1->name);
                    if (next->c1->prefix) free((void *)next->c1->prefix);
                    free(next->c1);
                }
                free(next);
            }
            free(cur);
        }
        if (elem->name && elem_name) free((void *)elem_name);
        if (elem->prefix && elem_pref) free((void *)elem_pref);
        free(elem);
    }

    if (doc) free(doc);
    if (vctxt) free(vctxt);

    return 0;
}