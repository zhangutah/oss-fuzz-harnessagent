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
// // static xmlHashedString
// //xmlParseQNameHashed(xmlParserCtxtPtr ctxt, xmlHashedString *prefix) {
// //    xmlHashedString l, p;
// //    int start, isNCName = 0;
// //
// //    l.name = NULL;
// //    p.name = NULL;
// //
// //    GROW;
// //    start = CUR_PTR - BASE_PTR;
// //
// //    l = xmlParseNCName(ctxt);
// //    if (l.name != NULL) {
// //        isNCName = 1;
// //        if (CUR == ':') {
// //            NEXT;
// //            p = l;
// //            l = xmlParseNCName(ctxt);
// //        }
// //    }
// //    if ((l.name == NULL) || (CUR == ':')) {
// //        xmlChar *tmp;
// //
// //        l.name = NULL;
// //        p.name = NULL;
// //        if ((isNCName == 0) && (CUR != ':'))
// //            return(l);
// //        tmp = xmlParseNmtoken(ctxt);
// //        if (tmp != NULL)
// //            xmlFree(tmp);
// //        l = xmlDictLookupHashed(ctxt->dict, BASE_PTR + start,
// //                                CUR_PTR - (BASE_PTR + start));
// //        if (l.name == NULL) {
// //            xmlErrMemory(ctxt);
// //            return(l);
// //        }
// //        xmlNsErr(ctxt, XML_NS_ERR_QNAME,
// //                 "Failed to parse QName '%s'\n", l.name, NULL, NULL);
// //    }
// //
// //    *prefix = p;
// //    return(l);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlChar * xmlParseNmtoken(xmlParserCtxt * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Project headers (use absolute paths returned by the codebase) */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Fuzzer entry point for xmlParseNmtoken(xmlParserCtxt *ctxt);
 *
 * This harness:
 *  - Initializes libxml2 parser subsystem.
 *  - Creates a memory parser context from the fuzzer-provided buffer.
 *  - Calls xmlParseNmtoken on that context.
 *  - Frees the returned xmlChar* (if any) and the parser context.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Initialize the parser library (safe to call multiple times). */
    xmlInitParser();

    /* xmlCreateMemoryParserCtxt expects an int size; cap to INT_MAX. */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a parser context that reads from the provided memory buffer. */
    xmlParserCtxt *ctxt = xmlCreateMemoryParserCtxt((const char *)Data, len);
    if (ctxt == NULL) return 0;

    /* Call the function under test. */
    xmlChar *res = xmlParseNmtoken(ctxt);

    /* Free any returned data and the parser context. */
    if (res != NULL) xmlFree(res);
    xmlFreeParserCtxt(ctxt);

    return 0;
}