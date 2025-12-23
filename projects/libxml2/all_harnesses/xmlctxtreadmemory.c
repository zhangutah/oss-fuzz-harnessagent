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
// // static xmlDoc *
// //xmlRelaxReadMemory(xmlRelaxNGParserCtxtPtr ctxt, const char *buf, int size) {
// //    xmlParserCtxtPtr pctxt;
// //    xmlDocPtr doc;
// //
// //    pctxt = xmlNewParserCtxt();
// //    if (pctxt == NULL) {
// //        xmlRngPErrMemory(ctxt);
// //        return(NULL);
// //    }
// //    if (ctxt->serror != NULL)
// //        xmlCtxtSetErrorHandler(pctxt, ctxt->serror, ctxt->userData);
// //    if (ctxt->resourceLoader != NULL)
// //        xmlCtxtSetResourceLoader(pctxt, ctxt->resourceLoader,
// //                                 ctxt->resourceCtxt);
// //    doc = xmlCtxtReadMemory(pctxt, buf, size, NULL, NULL, 0);
// //    xmlFreeParserCtxt(pctxt);
// //
// //    return(doc);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlCtxtReadMemory(xmlParserCtxt * ctxt, const char * buffer, int size, const char * URL, const char * encoding, int options);
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
#include <stdarg.h>

/* Use project absolute headers discovered from the workspace */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/* Suppress libxml error output to keep fuzzer logs clean */
static void xml_noop_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

/* Initialize / cleanup libxml once for the process */
__attribute__((constructor)) static void libxml_fuzz_init(void)
{
    xmlInitParser();
    /* Redirect error handler to no-op */
    xmlSetGenericErrorFunc(NULL, xml_noop_error);
}

__attribute__((destructor)) static void libxml_fuzz_cleanup(void)
{
    /* Cleanup global parser state */
    xmlCleanupParser();
}

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Data == NULL || Size == 0)
        return 0;

    /* xmlCtxtReadMemory expects an int for size */
    int in_size = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a new parser context for this input */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Use XML_PARSE_NONET to avoid any network activity during parsing */
    xmlDocPtr doc = xmlCtxtReadMemory(ctxt, (const char *)Data, in_size,
                                      /* URL */ NULL,
                                      /* encoding */ NULL,
                                      /* options */ XML_PARSE_NONET);

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Free the parser context */
    xmlFreeParserCtxt(ctxt);

    return 0;
}
