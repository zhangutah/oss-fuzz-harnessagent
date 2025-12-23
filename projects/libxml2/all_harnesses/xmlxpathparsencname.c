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
// // static xmlChar *
// //xmlXPathParseQName(xmlXPathParserContextPtr ctxt, xmlChar **prefix) {
// //    xmlChar *ret = NULL;
// //
// //    *prefix = NULL;
// //    ret = xmlXPathParseNCName(ctxt);
// //    if (ret && CUR == ':') {
// //        *prefix = ret;
// //	NEXT;
// //	ret = xmlXPathParseNCName(ctxt);
// //    }
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
//     xmlChar * xmlXPathParseNCName(xmlXPathParserContext * ctxt);
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
#include <libxml/xmlstring.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/*
 Fuzz driver for:
     xmlChar * xmlXPathParseNCName(xmlXPathParserContext * ctxt);

 Fuzzer entry point:
     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int libxml_initialized = 0;
    if (!libxml_initialized) {
        /* Initialize libxml once per process to ensure internal data is ready. */
        xmlInitParser();
        libxml_initialized = 1;
    }

    /* Accept zero-length input: treat as empty string. */
    size_t buf_len = Size;
    /* Allocate a nul-terminated buffer for xmlChar (which is unsigned char). */
    xmlChar *buf = (xmlChar *)malloc(buf_len + 1);
    if (buf == NULL) return 0;
    if (Data && buf_len > 0) {
        memcpy(buf, Data, buf_len);
    }
    buf[buf_len] = '\0';

    /* Allocate and initialize an xmlXPathParserContext.
       The implementation of xmlXPathParseNCName primarily reads ctxt->cur,
       so we set cur (and base) to our buffer and zero other fields. */
    xmlXPathParserContext *ctxt = (xmlXPathParserContext *)malloc(sizeof(xmlXPathParserContext));
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }
    memset(ctxt, 0, sizeof(*ctxt));

    ctxt->cur = buf;
    ctxt->base = buf;
    ctxt->error = 0;
    ctxt->context = NULL;
    ctxt->value = NULL;
    ctxt->valueNr = 0;
    ctxt->valueMax = 0;
    ctxt->valueTab = NULL;
    ctxt->comp = NULL;
    ctxt->xptr = 0;
    ctxt->ancestor = NULL;
    ctxt->valueFrame = 0;

    /* Call the function under test. */
    xmlChar *res = xmlXPathParseNCName(ctxt);

    /* Free any returned string with libxml's xmlFree (used by xmlStrndup). */
    if (res != NULL) xmlFree(res);

    /* Clean up. */
    free(ctxt);
    free(buf);

    /* Do not call xmlCleanupParser() here (expensive and global); the
       fuzzer process will exit when finished. */

    return 0;
}
