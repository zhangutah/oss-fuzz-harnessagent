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
//     xmlDoc * htmlReadDoc(const xmlChar * cur, const char * URL, const char * encoding, int options);
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

#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

/*
 * Fuzzer driver for:
 *   xmlDoc * htmlReadDoc(const xmlChar * cur, const char * URL, const char * encoding, int options);
 *
 * Entry point required by libFuzzer:
 *   int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 *
 * Notes:
 * - We null-terminate a copy of the input so htmlReadDoc can safely treat it as a C string.
 * - We derive the 'options' argument from up to the first 4 bytes of input to introduce variability.
 * - xmlInitParser() is called once on the first invocation.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* Initialize libxml2 parser (idempotent) */
        xmlInitParser();
        /* Disable loading external DTDs by default to avoid network/file access if available */
#ifdef XML_PARSE_NOENT
        /* nothing to set globally here reliably in all libxml2 versions */
#endif
        inited = 1;
    }

    if (Size == 0) {
        return 0;
    }

    /* Make a NUL-terminated copy of input data */
    char *input = (char*)malloc(Size + 1);
    if (!input) return 0;
    memcpy(input, Data, Size);
    input[Size] = '\0';

    /* Derive options from the first up-to-4 bytes of the input to vary parser flags */
    int options = 0;
    if (Size >= 4) {
        options = (int)((uint32_t)Data[0] |
                        ((uint32_t)Data[1] << 8) |
                        ((uint32_t)Data[2] << 16) |
                        ((uint32_t)Data[3] << 24));
    } else {
        for (size_t i = 0; i < Size && i < 4; ++i) {
            options |= (int)Data[i] << (8 * i);
        }
    }

    /* Call the target function. Pass NULL for URL and encoding. */
    xmlDocPtr doc = htmlReadDoc((const xmlChar *)input, NULL, NULL, options);

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    free(input);
    return 0;
}