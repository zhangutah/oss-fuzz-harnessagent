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
// // static void
// //xmlXPathNameFunction(xmlXPathParserContextPtr ctxt, int nargs)
// //{
// //    xmlXPathObjectPtr cur;
// //
// //    if (nargs == 0) {
// //	xmlXPathValuePush(ctxt, xmlXPathCacheNewNodeSet(ctxt, ctxt->context->node));
// //        nargs = 1;
// //    }
// //
// //    CHECK_ARITY(1);
// //    if ((ctxt->value == NULL) ||
// //        ((ctxt->value->type != XPATH_NODESET) &&
// //         (ctxt->value->type != XPATH_XSLT_TREE)))
// //        XP_ERROR(XPATH_INVALID_TYPE);
// //    cur = xmlXPathValuePop(ctxt);
// //
// //    if ((cur->nodesetval == NULL) || (cur->nodesetval->nodeNr == 0)) {
// //        xmlXPathValuePush(ctxt, xmlXPathCacheNewCString(ctxt, ""));
// //    } else {
// //        int i = 0;              /* Should be first in document order !!!!! */
// //
// //        switch (cur->nodesetval->nodeTab[i]->type) {
// //            case XML_ELEMENT_NODE:
// //            case XML_ATTRIBUTE_NODE:
// //		if (cur->nodesetval->nodeTab[i]->name[0] == ' ')
// //		    xmlXPathValuePush(ctxt,
// //			xmlXPathCacheNewCString(ctxt, ""));
// //		else if ((cur->nodesetval->nodeTab[i]->ns == NULL) ||
// //                         (cur->nodesetval->nodeTab[i]->ns->prefix == NULL)) {
// //		    xmlXPathValuePush(ctxt, xmlXPathCacheNewString(ctxt,
// //			    cur->nodesetval->nodeTab[i]->name));
// //		} else {
// //		    xmlChar *fullname;
// //
// //		    fullname = xmlBuildQName(cur->nodesetval->nodeTab[i]->name,
// //				     cur->nodesetval->nodeTab[i]->ns->prefix,
// //				     NULL, 0);
// //		    if (fullname == cur->nodesetval->nodeTab[i]->name)
// //			fullname = xmlStrdup(cur->nodesetval->nodeTab[i]->name);
// //		    if (fullname == NULL)
// //                        xmlXPathPErrMemory(ctxt);
// //		    xmlXPathValuePush(ctxt, xmlXPathCacheWrapString(ctxt, fullname));
// //                }
// //                break;
// //            default:
// //		xmlXPathValuePush(ctxt, xmlXPathCacheNewNodeSet(ctxt,
// //		    cur->nodesetval->nodeTab[i]));
// //                xmlXPathLocalNameFunction(ctxt, 1);
// //        }
// //    }
// //    xmlXPathReleaseObject(ctxt->context, cur);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     void xmlXPathLocalNameFunction(xmlXPathParserContext * ctxt, int nargs);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Use project headers found by static analysis */
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/xpathInternals.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

/*
 * Fuzzer entrypoint for xmlXPathLocalNameFunction
 *
 * Strategy:
 *  - Parse the fuzzer input as an XML document using xmlReadMemory.
 *  - Create an xmlXPathContext for that document.
 *  - Set the context node to the document root.
 *  - Create an xmlXPathParserContext (required by xmlXPathLocalNameFunction).
 *  - Call xmlXPathLocalNameFunction with nargs = 0 so it will operate on
 *    the current context node (root).
 *  - Clean up allocated structures.
 *
 * The driver avoids using lots of other XPath APIs and uses public/internal
 * declarations available in the headers included above.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize libxml once per call to be conservative for fuzzing harnesses. */
    xmlInitParser();

    if (Data == NULL || Size == 0)
        return 0;

    /* Parse input as an XML document. Use recover mode to get a doc where possible. */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzzed.xml", NULL, parseOptions);

    /* If parsing failed, create a minimal document so we still exercise the code path. */
    if (doc == NULL) {
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc == NULL)
            return 0;
        xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
        if (root == NULL) {
            xmlFreeDoc(doc);
            return 0;
        }
        xmlDocSetRootElement(doc, root);
    }

    /* Create an XPath evaluation context for the document. */
    xmlXPathContextPtr xpctxt = xmlXPathNewContext(doc);
    if (xpctxt == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Set the context node to the document root (if present). */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root != NULL) {
        /* xmlXPathSetContextNode is a public helper to set context->node safely */
        (void) xmlXPathSetContextNode(root, xpctxt);
    } else {
        /* If no root, default to NULL node (function handles missing ctxt->node). */
    }

    /* Create a parser context. The expression string isn't used by xmlXPathLocalNameFunction,
     * but xmlXPathNewParserContext requires a const xmlChar*; pass an empty string.
     */
    xmlXPathParserContextPtr pctxt = xmlXPathNewParserContext(BAD_CAST "", xpctxt);
    if (pctxt == NULL) {
        xmlXPathFreeContext(xpctxt);
        xmlFreeDoc(doc);
        return 0;
    }

    /* Call the target function. Use nargs = 0 to make it use ctxt->context->node. */
    xmlXPathLocalNameFunction(pctxt, 0);

    /* Cleanup */
    xmlXPathFreeParserContext(pctxt);
    xmlXPathFreeContext(xpctxt);
    xmlFreeDoc(doc);

    /* Optional: cleanup global parser state (safe to call repeatedly) */
    xmlCleanupParser();

    return 0;
}