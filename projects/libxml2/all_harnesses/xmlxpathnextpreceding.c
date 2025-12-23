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
//     xmlNode * xmlXPathNextPreceding(xmlXPathParserContext * ctxt, xmlNode * cur);
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

/* Use the internal header found in the project */
#include "/src/libxml2/include/libxml/xpathInternals.h"
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Fuzzer entry point for:
 *   xmlNode * xmlXPathNextPreceding(xmlXPathParserContext * ctxt, xmlNode * cur);
 *
 * Strategy:
 * - Parse the fuzz input as an XML document with xmlReadMemory.
 * - Create an xmlXPathContext for that document.
 * - Create an xmlXPathParserContext using a NUL-terminated copy of the fuzz input
 *   (treating the input also as an XPath expression).
 * - Repeatedly call xmlXPathNextPreceding starting from the document root
 *   (bounded iteration) to exercise the function.
 *
 * This driver tries to be defensive: it returns early if allocations/parsing fail.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0) return 0;

    /* Initialize the libxml2 parser library for this invocation */
    xmlInitParser();

    /* Parse the fuzz input as an XML document */
    /* Make a temporary NUL-terminated buffer for xmlReadMemory */
    char *xmlBuf = (char*)malloc(Size + 1);
    if (xmlBuf == NULL) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(xmlBuf, Data, Size);
    xmlBuf[Size] = '\0';

    /* Parse without noise to reduce stderr output in fuzzers */
    xmlDocPtr doc = xmlReadMemory(xmlBuf, (int)Size, "fuzz.xml", NULL,
                                 XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    free(xmlBuf);

    if (doc == NULL) {
        /* Not a valid XML doc; still exercise XPath creation using an empty doc? skip. */
        xmlCleanupParser();
        return 0;
    }

    /* Create an XPath context for the parsed document */
    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /*
     * Prepare an XPath expression from the fuzz input as well.
     * Use a NUL-terminated copy to be safe for C string APIs.
     */
    char *expr = (char*)malloc(Size + 1);
    if (expr == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    memcpy(expr, Data, Size);
    expr[Size] = '\0';

    /* Create a parser context for the XPath expression */
    xmlXPathParserContextPtr pctx = xmlXPathNewParserContext((const xmlChar *)expr, xpathCtx);
    free(expr);

    if (pctx == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Start from the document root element as the 'cur' node */
    xmlNodePtr cur = xmlDocGetRootElement(doc);

    /* Call xmlXPathNextPreceding repeatedly to exercise traversal logic.
       Bound the loop to avoid pathological long runs. */
    const int max_iterations = 1024;
    for (int i = 0; i < max_iterations && cur != NULL; ++i) {
        /* The function under test */
        xmlNodePtr next = xmlXPathNextPreceding(pctx, cur);
        /* Use the result in a trivial way to avoid being optimized out */
        cur = next;
    }

    /* Clean up all created objects */
    xmlXPathFreeParserContext(pctx);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);

    /* Cleanup parser global state */
    xmlCleanupParser();

    return 0;
}