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
// //testPushCDataEnd(void) {
// //    int err = 0;
// //    int k;
// //
// //    for (k = 0; k < 4; k++) {
// //        xmlBufferPtr buf;
// //        xmlChar *chunk;
// //        xmlParserCtxtPtr ctxt;
// //        int i;
// //
// //        ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
// //        xmlCtxtSetOptions(ctxt, XML_PARSE_NOERROR);
// //
// //        /*
// //         * Push parse text data with ']]>' split across chunks.
// //         */
// //        buf = xmlBufferCreate();
// //        xmlBufferCCat(buf, "<doc>");
// //
// //        /*
// //         * Also test xmlParseCharDataCopmlex
// //         */
// //        if (k & 1)
// //            xmlBufferCCat(buf, "x");
// //        else
// //            xmlBufferCCat(buf, "\xC3\xA4");
// //
// //        /*
// //         * Create enough data to trigger a "characters" SAX callback.
// //         * (XML_PARSER_BIG_BUFFER_SIZE = 300)
// //         */
// //        for (i = 0; i < 2000; i++)
// //            xmlBufferCCat(buf, "x");
// //
// //        if (k & 2)
// //            xmlBufferCCat(buf, "]");
// //        else
// //            xmlBufferCCat(buf, "]]");
// //
// //        chunk = xmlBufferDetach(buf);
// //        xmlBufferFree(buf);
// //
// //        xmlParseChunk(ctxt, (char *) chunk, xmlStrlen(chunk), 0);
// //        if (k & 2)
// //            xmlParseChunk(ctxt, "]>xxx</doc>", 11, 1);
// //        else
// //            xmlParseChunk(ctxt, ">xxx</doc>", 10, 1);
// //
// //        if (ctxt->errNo != XML_ERR_MISPLACED_CDATA_END) {
// //            fprintf(stderr, "xmlParseChunk failed to detect CData end: %d\n",
// //                    ctxt->errNo);
// //            err = 1;
// //        }
// //
// //        xmlFree(chunk);
// //        xmlFreeDoc(ctxt->myDoc);
// //        xmlFreeParserCtxt(ctxt);
// //    }
// //
// //    return err;
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlParseChunk(xmlParserCtxt * ctxt, const char * chunk, int size, int terminate);
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

/* Use the project header discovered for xmlParseChunk */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzzer entry point for xmlParseChunk
 This driver:
 - Initializes the libxml2 parser library once.
 - Creates a push parser context.
 - Feeds the fuzzer data to xmlParseChunk (as one chunk).
 - Cleans up parser structures.
 Notes:
 - Size is clamped to INT_MAX because xmlParseChunk takes an int size parameter.
 - If Size == 0, an empty chunk is passed with terminate == 1.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        /* Initialize the parser library once per process */
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL) {
        return 0;
    }

    /* Clamp the size to INT_MAX to avoid overflow when casting to int */
    int sz = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a push parser context. Use NULL SAX handler and no initial chunk. */
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, NULL, 0, NULL);
    if (ctxt == NULL) {
        return 0;
    }

    /* Feed the entire input as a single chunk and indicate termination. */
    if (sz > 0) {
        /* Cast Data to const char* as required by xmlParseChunk */
        xmlParseChunk(ctxt, (const char *)Data, sz, 1);
    } else {
        /* size == 0: pass empty chunk and terminate */
        xmlParseChunk(ctxt, "", 0, 1);
    }

    /* Free any parsed document if created */
    if (ctxt->myDoc)
        xmlFreeDoc(ctxt->myDoc);

    /* Free the parser context */
    xmlFreeParserCtxt(ctxt);

    /* Do not call xmlCleanupParser() here 	6 it would undo global init for subsequent fuzzing calls. */

    return 0;
}