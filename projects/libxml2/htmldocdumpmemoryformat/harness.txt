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
// //testHtmlInsertMetaEncoding(void) {
// //    /* We currently require a head element to be present. */
// //    const char *html =
// //        "<html>"
// //        "<head></head>"
// //        "<body>text</body>"
// //        "</html>\n";
// //    const char *expect =
// //        "<html>"
// //        "<head><meta charset=\"utf-8\"></head>"
// //        "<body>text</body>"
// //        "</html>\n";
// //    htmlDocPtr doc;
// //    xmlBufferPtr buf;
// //    xmlSaveCtxtPtr save;
// //    xmlChar *out;
// //    int size, err = 0;
// //
// //
// //    doc = htmlReadDoc(BAD_CAST html, NULL, NULL, HTML_PARSE_NODEFDTD);
// //
// //    /* xmlSave updates meta tags */
// //    buf = xmlBufferCreate();
// //    save = xmlSaveToBuffer(buf, "utf-8", 0);
// //    xmlSaveDoc(save, doc);
// //    xmlSaveClose(save);
// //    if (!xmlStrEqual(xmlBufferContent(buf), BAD_CAST expect)) {
// //        fprintf(stderr, "meta tag insertion failed when serializing\n");
// //        err = 1;
// //    }
// //    xmlBufferFree(buf);
// //
// //    htmlSetMetaEncoding(doc, BAD_CAST "utf-8");
// //    /* htmlDocDumpMemoryFormat doesn't update meta tags */
// //    htmlDocDumpMemoryFormat(doc, &out, &size, 0);
// //    if (!xmlStrEqual(out, BAD_CAST expect)) {
// //        fprintf(stderr, "htmlSetMetaEncoding insertion failed\n");
// //        err = 1;
// //    }
// //    xmlFree(out);
// //
// //    xmlFreeDoc(doc);
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
//     void htmlDocDumpMemoryFormat(xmlDoc * cur, xmlChar ** mem, int * size, int format);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

/* Use project absolute headers as provided by the workspace tools */
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include "/src/libxml2/include/libxml/HTMLtree.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzzer entry point expected by libFuzzer / LLVM:
 extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the parser library (idempotent) */
    xmlInitParser();

    /* Protect against extremely large sizes when casting to int */
    int int_size = (Size > INT_MAX) ? INT_MAX : (int)Size;
    /* Further cap to avoid pathological allocations during fuzzing */
    const int MAX_SAFE_SIZE = 1000000;
    if (int_size > MAX_SAFE_SIZE) int_size = MAX_SAFE_SIZE;

    /* Choose a format value derived from input to increase coverage variety */
    int format = (Data[0] & 1); /* 0 or 1 */

    /* Parse the input buffer as HTML into an xmlDoc (htmlDoc) */
    /* htmlReadMemory(const char *buffer, int size, const char *URL,
                     const char *encoding, int options); */
    xmlDocPtr doc = htmlReadMemory((const char *)Data, int_size, NULL, NULL, 0);
    if (doc == NULL) {
        /* Nothing parsed; cleanup parser state and return */
        xmlCleanupParser();
        return 0;
    }

    /* Dump the document to memory using the target function under test */
    xmlChar *out_mem = NULL;
    int out_size = 0;
    /* void htmlDocDumpMemoryFormat(xmlDoc * cur, xmlChar ** mem, int * size, int format); */
    htmlDocDumpMemoryFormat(doc, &out_mem, &out_size, format);

    /* Free the returned memory if any */
    if (out_mem != NULL) {
        xmlFree(out_mem);
        out_mem = NULL;
    }

    /* Free the parsed document */
    xmlFreeDoc(doc);

    /*
      Note: xmlCleanupParser releases global parser state. Calling it here is fine
      for fuzz drivers, though it can be omitted if the harness prefers to
      initialize/cleanup at process boundaries.
    */
    xmlCleanupParser();

    return 0;
}
