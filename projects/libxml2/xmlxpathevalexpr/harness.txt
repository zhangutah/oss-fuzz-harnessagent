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
// // xmlXPathObject *
// //xmlXPathEval(const xmlChar *str, xmlXPathContext *ctx) {
// //    xmlXPathParserContextPtr ctxt;
// //    xmlXPathObjectPtr res;
// //
// //    if (ctx == NULL)
// //        return(NULL);
// //
// //    xmlInitParser();
// //
// //    xmlResetError(&ctx->lastError);
// //
// //    ctxt = xmlXPathNewParserContext(str, ctx);
// //    if (ctxt == NULL)
// //        return NULL;
// //    xmlXPathEvalExpr(ctxt);
// //
// //    if (ctxt->error != XPATH_EXPRESSION_OK) {
// //	res = NULL;
// //    } else if (ctxt->valueNr != 1) {
// //        xmlXPathErr(ctxt, XPATH_STACK_ERROR);
// //	res = NULL;
// //    } else {
// //	res = xmlXPathValuePop(ctxt);
// //    }
// //
// //    xmlXPathFreeParserContext(ctxt);
// //    return(res);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     void xmlXPathEvalExpr(xmlXPathParserContext * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Cap allocation to avoid excessive memory use from very large inputs. */
    const size_t MAX_COPY = 65536;
    size_t len = Size;
    if (len > MAX_COPY) len = MAX_COPY;

    /* Copy data to a null-terminated buffer to use as an XPath expression. */
    char *expr = (char *)malloc(len + 1);
    if (expr == NULL)
        return 0;
    memcpy(expr, Data, len);
    expr[len] = '\0';

    /* Initialize libxml parser library (no-op if already initialized). */
    xmlInitParser();

    /* Create an XPath context. Passing a NULL document is acceptable for many uses. */
    xmlXPathContextPtr xpathCtxt = xmlXPathNewContext(NULL);
    if (xpathCtxt == NULL) {
        free(expr);
        xmlCleanupParser();
        return 0;
    }

    /* Create a parser context with the input expression. */
    xmlXPathParserContextPtr pctxt = xmlXPathNewParserContext((const xmlChar *)expr, xpathCtxt);
    if (pctxt == NULL) {
        xmlXPathFreeContext(xpathCtxt);
        free(expr);
        xmlCleanupParser();
        return 0;
    }

    /* Call the target function under test. */
    xmlXPathEvalExpr(pctxt);

    /* Clean up parser context and XPath context. xmlXPathFreeParserContext will
       free any values allocated on the parser stack. */
    xmlXPathFreeParserContext(pctxt);
    xmlXPathFreeContext(xpathCtxt);

    free(expr);

    /* Optional: cleanup global parser state. In long-running fuzzers this can be
       omitted to retain parser caches; calling it is safer for isolated runs. */
    xmlCleanupParser();

    return 0;
}
