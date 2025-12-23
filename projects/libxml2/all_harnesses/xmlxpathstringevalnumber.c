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
// //xmlXPathNumberFunction(xmlXPathParserContext *ctxt, int nargs) {
// //    xmlXPathObjectPtr cur;
// //    double res;
// //
// //    if (ctxt == NULL) return;
// //    if (nargs == 0) {
// //	if (ctxt->context->node == NULL) {
// //	    xmlXPathValuePush(ctxt, xmlXPathCacheNewFloat(ctxt, 0.0));
// //	} else {
// //	    xmlChar* content = xmlNodeGetContent(ctxt->context->node);
// //            if (content == NULL)
// //                xmlXPathPErrMemory(ctxt);
// //
// //	    res = xmlXPathStringEvalNumber(content);
// //	    xmlXPathValuePush(ctxt, xmlXPathCacheNewFloat(ctxt, res));
// //	    xmlFree(content);
// //	}
// //	return;
// //    }
// //
// //    CHECK_ARITY(1);
// //    cur = xmlXPathValuePop(ctxt);
// //    if (cur->type != XPATH_NUMBER) {
// //        double floatval;
// //
// //        floatval = xmlXPathCastToNumberInternal(ctxt, cur);
// //        xmlXPathReleaseObject(ctxt->context, cur);
// //        cur = xmlXPathCacheNewFloat(ctxt, floatval);
// //    }
// //    xmlXPathValuePush(ctxt, cur);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     double xmlXPathStringEvalNumber(const xmlChar * str);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     double xmlXPathStringEvalNumber(const xmlChar * str);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Note: This driver includes project headers with absolute paths as returned
// by the codebase search. Adjust includes if building outside the original
// source tree.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Project headers (absolute paths from the repo). If these are not found
   in your build environment, change to the appropriate include paths:
   e.g. #include <libxml/xpathInternals.h> and link with -lxml2. */
#include "/src/libxml2/include/libxml/xpathInternals.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive checks */
    if (Data == NULL || Size == 0) return 0;

    /* Ensure libxml is initialized once. */
    static int xml_inited = 0;
    if (!xml_inited) {
        xmlInitParser();
        xml_inited = 1;
    }

    /* Copy input into a null-terminated buffer expected by xmlXPathStringEvalNumber. */
    xmlChar *buf = (xmlChar *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Call the target function. */
    double result = xmlXPathStringEvalNumber((const xmlChar *)buf);

    /* Use the result in a way that prevents the compiler from optimizing the call away. */
    if (result != result) {
        /* result is NaN; do nothing special, just an observable check */
        volatile int sink = 0;
        (void)sink;
    }

    free(buf);
    return 0;
}
