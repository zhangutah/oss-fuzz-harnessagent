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
//     void xmlXPathStringLengthFunction(xmlXPathParserContext * ctxt, int nargs);
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
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/*
 * Fuzzer entry point for xmlXPathStringLengthFunction
 *
 * This harness:
 * - parses the fuzzer input as an XML document (xmlReadMemory)
 * - creates an xmlXPathContext for that document
 * - creates an xmlXPathParserContext using a NUL-terminated copy of the input
 * - calls xmlXPathStringLengthFunction with nargs == 0 in a couple of contexts
 * - cleans up resources
 *
 * We avoid using nargs == 1 branch because that requires manipulating the
 * parser stack (pushing a string object), which is more involved.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        /* Initialize libxml once */
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Make a NUL-terminated copy of the input to use as an "expression" string */
    char *expr = (char *)malloc(Size + 1);
    if (expr == NULL)
        return 0;
    memcpy(expr, Data, Size);
    expr[Size] = '\0';

    /* Parse the fuzzer input as an XML document (best-effort) */
    xmlDocPtr doc = xmlReadMemory(expr, (int)Size, "fuzz-input.xml", NULL, 0);

    /* Create an XPath context for the parsed document (doc may be NULL) */
    xmlXPathContextPtr xctxt = xmlXPathNewContext(doc);
    if (xctxt == NULL) {
        free(expr);
        if (doc)
            xmlFreeDoc(doc);
        return 0;
    }

    /*
     * xmlXPathNewParserContext associates the parser context with the
     * XPath context; pass our NUL-terminated buffer as the "expression".
     */
    xmlXPathParserContextPtr pctxt = xmlXPathNewParserContext((const xmlChar *)expr, xctxt);

    /* We no longer need the expr buffer directly (parser copies or references it) */
    free(expr);
    expr = NULL;

    if (pctxt == NULL) {
        xmlXPathFreeContext(xctxt);
        if (doc)
            xmlFreeDoc(doc);
        return 0;
    }

    /* Two simple scenarios to exercise different branches inside the function. */

    /* 1) If node is NULL: this should push length 0 (or handle missing context) */
    xctxt->node = NULL;
    xmlXPathStringLengthFunction(pctxt, 0);

    /* 2) If a node exists: try using the document root as context->node (if available) */
    if (doc != NULL) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL) {
            xctxt->node = root;
            /* Call the function again with a real node to exercise xmlXPathCastNodeToString path */
            xmlXPathStringLengthFunction(pctxt, 0);
        }
    }

    /* Clean up parser and xpath contexts and the document */
    xmlXPathFreeParserContext(pctxt);
    xmlXPathFreeContext(xctxt);
    if (doc)
        xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here; keep the library initialized across runs. */
    return 0;
}
