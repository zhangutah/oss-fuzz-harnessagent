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
// // static int
// //xmlXPathCompareNodeSetFloat(xmlXPathParserContextPtr ctxt, int inf, int strict,
// //	                    xmlXPathObjectPtr arg, xmlXPathObjectPtr f) {
// //    int i, ret = 0;
// //    xmlNodeSetPtr ns;
// //    xmlChar *str2;
// //
// //    if ((f == NULL) || (arg == NULL) ||
// //	((arg->type != XPATH_NODESET) && (arg->type != XPATH_XSLT_TREE))) {
// //	xmlXPathReleaseObject(ctxt->context, arg);
// //	xmlXPathReleaseObject(ctxt->context, f);
// //        return(0);
// //    }
// //    ns = arg->nodesetval;
// //    if (ns != NULL) {
// //	for (i = 0;i < ns->nodeNr;i++) {
// //	     str2 = xmlXPathCastNodeToString(ns->nodeTab[i]);
// //	     if (str2 != NULL) {
// //		 xmlXPathValuePush(ctxt, xmlXPathCacheNewString(ctxt, str2));
// //		 xmlFree(str2);
// //		 xmlXPathNumberFunction(ctxt, 1);
// //		 xmlXPathValuePush(ctxt, xmlXPathCacheObjectCopy(ctxt, f));
// //		 ret = xmlXPathCompareValues(ctxt, inf, strict);
// //		 if (ret)
// //		     break;
// //	     } else {
// //                 xmlXPathPErrMemory(ctxt);
// //             }
// //	}
// //    }
// //    xmlXPathReleaseObject(ctxt->context, arg);
// //    xmlXPathReleaseObject(ctxt->context, f);
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
//     int xmlXPathCompareValues(xmlXPathParserContext * ctxt, int inf, int strict);
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

/* Use the project-provided internal header for xpath parser/context helpers */
#include "/src/libxml2/include/libxml/xpathInternals.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/*
 * This fuzzer builds a minimal XML document and an XPath parser context,
 * pushes two numeric values on the parser value stack, then calls
 * xmlXPathCompareValues to exercise numeric comparison logic as well as
 * conversion paths inside the XPath implementation.
 *
 * Layout of input bytes:
 *  - byte 0: inf flag (low bit)
 *  - byte 1: strict flag (low bit)
 *  - remaining bytes: used to build the expression string passed to the parser
 *                     and to synthesize two doubles when possible.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();

    /* Derive flags from the first two bytes (if present) */
    int inf = 0;
    int strict = 0;
    if (Size >= 1) inf = Data[0] & 1;
    if (Size >= 2) strict = Data[1] & 1;

    /* Prepare an expression string from the remaining input bytes.
       Ensure NUL-termination. If no bytes remain, use an empty expression. */
    const char *expr_cstr = "";
    char *expr_buf = NULL;
    if (Size > 2) {
        size_t expr_len = Size - 2;
        /* Limit expression size to a reasonable bound to avoid huge allocations */
        const size_t MAX_EXPR = 4096;
        if (expr_len > MAX_EXPR) expr_len = MAX_EXPR;
        expr_buf = (char *)malloc(expr_len + 1);
        if (expr_buf == NULL) {
            /* memory allocation failed; clean up and return */
            return 0;
        }
        memcpy(expr_buf, Data + 2, expr_len);
        expr_buf[expr_len] = '\0';
        expr_cstr = expr_buf;
    }

    /* Build a minimal xmlDoc to attach to the XPath context.
       Use xmlNewDoc and xmlNewNode to avoid parsing complexities. */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL) {
        free(expr_buf);
        return 0;
    }
    xmlNodePtr root = xmlNewNode(NULL, (const xmlChar *)"root");
    if (root == NULL) {
        xmlFreeDoc(doc);
        free(expr_buf);
        return 0;
    }
    xmlDocSetRootElement(doc, root);

    /* Create an XPath evaluation context associated with the document */
    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(doc);
    if (xpathCtx == NULL) {
        xmlFreeDoc(doc);
        free(expr_buf);
        return 0;
    }

    /* Create an XPath parser context with the expression string */
    xmlXPathParserContextPtr parserCtx =
        xmlXPathNewParserContext((const xmlChar *)expr_cstr, xpathCtx);
    if (parserCtx == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        free(expr_buf);
        return 0;
    }

    /* Synthesize two doubles from the input (if possible) to push as values.
       If insufficient data, default to 0.0. */
    double val1 = 0.0, val2 = 0.0;
    if (Size >= 10) {
        /* Use 8 bytes for val1 starting at Data[2] if available */
        uint64_t u1 = 0, u2 = 0;
        size_t avail = Size - 2;
        /* Read up to 8 bytes for each value safely */
        size_t toRead1 = avail >= 8 ? 8 : avail;
        memcpy(&u1, Data + 2, toRead1);
        if (avail > toRead1) {
            size_t toRead2 = (avail - toRead1) >= 8 ? 8 : (avail - toRead1);
            memcpy(&u2, Data + 2 + toRead1, toRead2);
        }
        /* reinterpret bits as double to exercise NaN/Inf/denorm cases */
        memcpy(&val1, &u1, sizeof(double));
        memcpy(&val2, &u2, sizeof(double));
    } else if (Size >= 6) {
        /* Fallback: build two 32-bit bit patterns */
        uint32_t w1 = 0, w2 = 0;
        size_t avail = Size - 2;
        size_t toRead1 = avail >= 4 ? 4 : avail;
        memcpy(&w1, Data + 2, toRead1);
        if (avail > toRead1) {
            size_t toRead2 = (avail - toRead1) >= 4 ? 4 : (avail - toRead1);
            memcpy(&w2, Data + 2 + toRead1, toRead2);
        }
        double tmp1 = 0.0, tmp2 = 0.0;
        memcpy(&tmp1, &w1, sizeof(uint32_t));
        memcpy(&tmp2, &w2, sizeof(uint32_t));
        val1 = tmp1;
        val2 = tmp2;
    } else {
        /* Not enough data to form interesting numbers; use small constants */
        val1 = (double)(Size);
        val2 = (double)(Size ? Data[Size - 1] : 0);
    }

    /* Push two numeric values onto the parser value stack */
    xmlXPathObjectPtr obj1 = xmlXPathNewFloat(val1);
    xmlXPathObjectPtr obj2 = xmlXPathNewFloat(val2);
    if (obj1 != NULL) xmlXPathValuePush(parserCtx, obj1);
    if (obj2 != NULL) xmlXPathValuePush(parserCtx, obj2);

    /* Now call the function under test. This will pop and operate on the pushed values. */
    /* We ignore the return value; the goal is to exercise code paths. */
    (void)xmlXPathCompareValues(parserCtx, inf, strict);

    /* Cleanup: free parser context, XPath context and document.
       xmlXPathFreeParserContext will release remaining values on the stack. */
    xmlXPathFreeParserContext(parserCtx);
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);

    free(expr_buf);

    /* Note: keeping xmlCleanupParser() out of the hot path is often recommended
       because it deinitializes global state; the fuzzer harness runner usually
       calls it when the process exits. If desired, it could be invoked here. */

    return 0;
}
