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
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     void xmlXPathTranslateFunction(xmlXPathParserContext * ctxt, int nargs);
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

/*
 * Fuzz driver for:
 *   void xmlXPathTranslateFunction(xmlXPathParserContext * ctxt, int nargs);
 *
 * This driver builds a minimal libxml2 XPath parser context, pushes three
 * string arguments on the parser value stack (str, from, to) using
 * xmlXPathNewCString and xmlXPathValuePush, then calls
 * xmlXPathTranslateFunction(ctxt, 3).
 *
 * The fuzzer entry point is LLVMFuzzerTestOneInput.
 */

#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize parser (safe to call repeatedly) */
    xmlInitParser();

    /* Create a small empty document and XPath context for the parser context */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    xmlXPathContextPtr xpctxt = xmlXPathNewContext(doc);
    if (xpctxt == NULL) {
        if (doc) xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Create a parser context. The expression string here is unused by the
     * translate function, but xmlXPathNewParserContext expects one.
     */
    xmlXPathParserContextPtr pctxt = xmlXPathNewParserContext((const xmlChar *)"", xpctxt);
    if (pctxt == NULL) {
        xmlXPathFreeContext(xpctxt);
        if (doc) xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Split the fuzz input into three C-strings: str, from, to.
     * If Size == 0, use empty strings.
     */
    size_t n1 = 0, n2 = 0, n3 = 0;
    if (Size == 0) {
        n1 = n2 = n3 = 0;
    } else {
        /* Simple deterministic split */
        n1 = Size / 3;
        n2 = (Size - n1) / 2;
        n3 = Size - n1 - n2;
        if (n1 == 0 && Size > 0) n1 = 1;
        if (n2 == 0 && (Size - n1) > 0) n2 = 1;
        n3 = (Size >= n1 + n2) ? (Size - n1 - n2) : 0;
    }

    char *s1 = (char *)malloc(n1 + 1);
    char *s2 = (char *)malloc(n2 + 1);
    char *s3 = (char *)malloc(n3 + 1);
    if (!s1 || !s2 || !s3) {
        free(s1); free(s2); free(s3);
        xmlXPathFreeParserContext(pctxt);
        xmlXPathFreeContext(xpctxt);
        if (doc) xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Fill buffers from Data */
    size_t off = 0;
    if (n1 > 0) {
        memcpy(s1, Data + off, n1);
        off += n1;
    }
    s1[n1] = '\0';

    if (n2 > 0 && off < Size) {
        memcpy(s2, Data + off, n2);
        off += n2;
    } else {
        /* if not enough data left, fill with zeros */
        memset(s2, 0, n2);
    }
    s2[n2] = '\0';

    if (n3 > 0 && off < Size) {
        memcpy(s3, Data + off, n3);
        off += n3;
    } else {
        memset(s3, 0, n3);
    }
    s3[n3] = '\0';

    /* Create XPath string objects: push in order (str, from, to) so pops
     * inside the function yield to, from, str as expected.
     */
    xmlXPathObjectPtr obj_str  = xmlXPathNewCString(s1);
    xmlXPathObjectPtr obj_from = xmlXPathNewCString(s2);
    xmlXPathObjectPtr obj_to   = xmlXPathNewCString(s3);

    /* If any creation failed, cleanup and return. The parser context free
     * will only be called if we pushed something; ensure we don't push NULL.
     */
    if (obj_str == NULL || obj_from == NULL || obj_to == NULL) {
        /* Free objects if created */
        if (obj_str) xmlXPathFreeObject(obj_str);
        if (obj_from) xmlXPathFreeObject(obj_from);
        if (obj_to) xmlXPathFreeObject(obj_to);
        free(s1); free(s2); free(s3);
        xmlXPathFreeParserContext(pctxt);
        xmlXPathFreeContext(xpctxt);
        if (doc) xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Push in order: str, from, to */
    xmlXPathValuePush(pctxt, obj_str);
    xmlXPathValuePush(pctxt, obj_from);
    xmlXPathValuePush(pctxt, obj_to);

    /* Call the function under test with nargs = 3 */
    xmlXPathTranslateFunction(pctxt, 3);

    /* Cleanup: xmlXPathFreeParserContext should free any objects left on the
     * parser's value stack and release resources associated with pctxt.
     */
    xmlXPathFreeParserContext(pctxt);

    /* Free XPath context and document */
    xmlXPathFreeContext(xpctxt);
    if (doc) xmlFreeDoc(doc);

    free(s1); free(s2); free(s3);

    /* Optional: cleanup global parser state (may be a no-op in many harnesses) */
    xmlCleanupParser();

    return 0;
}