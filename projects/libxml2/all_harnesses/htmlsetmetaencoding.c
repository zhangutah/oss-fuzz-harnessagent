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
// //testHtmlUpdateMetaEncoding(void) {
// //    /* We rely on the implementation adjusting all meta tags */
// //    const char *html =
// //        "<html>\n"
// //        "    <head>\n"
// //        "        <meta charset=\"utf-8\">\n"
// //        "        <meta charset=\"  foo  \">\n"
// //        "        <meta charset=\"\">\n"
// //        "        <" MHE " content=\"text/html; ChArSeT=foo\">\n"
// //        "        <" MHE " content=\"text/html; charset = \">\n"
// //        "        <" MHE " content=\"text/html; charset = '  foo  '\">\n"
// //        "        <" MHE " content=\"text/html; charset = '  foo  \">\n"
// //        "        <" MHE " content='text/html; charset = \"  foo  \"'>\n"
// //        "        <" MHE " content='text/html; charset = \"  foo  '>\n"
// //        "        <" MHE " content=\"charset ; charset = bar; baz\">\n"
// //        "        <" MHE " content=\"text/html\">\n"
// //        "        <" MHE " content=\"\">\n"
// //        "        <" MHE ">\n"
// //        "    </head>\n"
// //        "    <body></body>\n"
// //        "</html>\n";
// //    const char *expect =
// //        "<html>\n"
// //        "    <head>\n"
// //        "        <meta charset=\"utf-8\">\n"
// //        "        <meta charset=\"  utf-8  \">\n"
// //        "        <meta charset=\"utf-8\">\n"
// //        "        <" MHE " content=\"text/html; ChArSeT=utf-8\">\n"
// //        "        <" MHE " content=\"text/html; charset = \">\n"
// //        "        <" MHE " content=\"text/html; charset = '  utf-8  '\">\n"
// //        "        <" MHE " content=\"text/html; charset = '  foo  \">\n"
// //        "        <" MHE " content=\"text/html; charset = &quot;  utf-8  &quot;\">\n"
// //        "        <" MHE " content=\"text/html; charset = &quot;  foo  \">\n"
// //        "        <" MHE " content=\"charset ; charset = utf-8; baz\">\n"
// //        "        <" MHE " content=\"text/html\">\n"
// //        "        <" MHE " content=\"\">\n"
// //        "        <" MHE ">\n"
// //        "    </head>\n"
// //        "    <body></body>\n"
// //        "</html>\n";
// //    htmlDocPtr doc;
// //    xmlBufferPtr buf;
// //    xmlSaveCtxtPtr save;
// //    xmlChar *out;
// //    int size, err = 0;
// //
// //    doc = htmlReadDoc(BAD_CAST html, NULL, NULL, HTML_PARSE_NODEFDTD);
// //
// //    /* xmlSave updates meta tags */
// //    buf = xmlBufferCreate();
// //    save = xmlSaveToBuffer(buf, NULL, 0);
// //    xmlSaveDoc(save, doc);
// //    xmlSaveClose(save);
// //    if (!xmlStrEqual(xmlBufferContent(buf), BAD_CAST expect)) {
// //        fprintf(stderr, "meta tag update failed when serializing\n");
// //        err = 1;
// //    }
// //    xmlBufferFree(buf);
// //
// //    xmlFree((xmlChar *) doc->encoding);
// //    doc->encoding = NULL;
// //    htmlSetMetaEncoding(doc, BAD_CAST "utf-8");
// //    /* htmlDocDumpMemoryFormat doesn't update meta tags */
// //    htmlDocDumpMemoryFormat(doc, &out, &size, 0);
// //    if (!xmlStrEqual(out, BAD_CAST expect)) {
// //        fprintf(stderr, "htmlSetMetaEncoding update failed\n");
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
//     int htmlSetMetaEncoding(xmlDoc * doc, const xmlChar * encoding);
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
#include <limits.h>

/* Project headers (use absolute paths as provided) */
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include "/src/libxml2/include/libxml/HTMLtree.h"

/*
 Fuzz driver for:
   int htmlSetMetaEncoding(xmlDoc * doc, const xmlChar * encoding);

 Strategy:
 - Parse the fuzzer input as an HTML document using htmlReadMemory.
 - Use the (NUL-terminated) input buffer as the encoding string passed to
   htmlSetMetaEncoding.
 - If parsing fails, create an empty HTML doc via htmlNewDoc and call the
   function on that.
 - Ensure xmlInitParser() is called once.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        /* Initialize libxml2 parser once */
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Cap Size to INT_MAX to avoid truncation issues with htmlReadMemory */
    if (Size > (size_t)INT_MAX)
        Size = (size_t)INT_MAX;

    /* Create a NUL-terminated buffer for parser and encoding */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Parse the input as an HTML document. Use recover/noerror/nowarning to
       avoid printing to stderr during fuzzing. */
    htmlDocPtr hdoc = htmlReadMemory(buf, (int)Size, NULL, NULL,
                                     HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING);

    if (hdoc != NULL) {
        /* Pass the buffer as the encoding (xmlChar is unsigned char) */
        (void) htmlSetMetaEncoding((xmlDoc *)hdoc, (const xmlChar *)buf);
        xmlFreeDoc((xmlDocPtr)hdoc);
    } else {
        /* Fallback: create a minimal HTML doc and call the API */
        xmlDocPtr doc = htmlNewDoc((const xmlChar *)NULL, (const xmlChar *)NULL);
        if (doc != NULL) {
            (void) htmlSetMetaEncoding(doc, (const xmlChar *)buf);
            xmlFreeDoc(doc);
        }
    }

    free(buf);
    return 0;
}