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
// //testReaderContent(void) {
// //    xmlTextReader *reader;
// //    const xmlChar *xml = BAD_CAST "<d>x<e>y</e><f>z</f></d>";
// //    xmlChar *string;
// //    int err = 0;
// //
// //    reader = xmlReaderForDoc(xml, NULL, NULL, 0);
// //    xmlTextReaderRead(reader);
// //
// //    string = xmlTextReaderReadOuterXml(reader);
// //    if (!xmlStrEqual(string, xml)) {
// //        fprintf(stderr, "xmlTextReaderReadOuterXml failed\n");
// //        err = 1;
// //    }
// //    xmlFree(string);
// //
// //    string = xmlTextReaderReadInnerXml(reader);
// //    if (!xmlStrEqual(string, BAD_CAST "x<e>y</e><f>z</f>")) {
// //        fprintf(stderr, "xmlTextReaderReadInnerXml failed\n");
// //        err = 1;
// //    }
// //    xmlFree(string);
// //
// //    string = xmlTextReaderReadString(reader);
// //    if (!xmlStrEqual(string, BAD_CAST "xyz")) {
// //        fprintf(stderr, "xmlTextReaderReadString failed\n");
// //        err = 1;
// //    }
// //    xmlFree(string);
// //
// //    xmlFreeTextReader(reader);
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
//     xmlChar * xmlTextReaderReadString(xmlTextReader * reader);
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

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlmemory.h>

/*
 Fuzzer entry point for:
     xmlChar * xmlTextReaderReadString(xmlTextReader * reader);

 This harness creates an xmlTextReader from the provided input bytes,
 iterates the document with xmlTextReaderRead, calls xmlTextReaderReadString
 on each node, and frees any returned xmlChar* with xmlFree.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the library (safe to call repeatedly) */
    xmlInitParser();

    /* xmlReaderForMemory expects an int size; clamp to INT_MAX if needed */
    int bufSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create the reader from the raw input buffer. URL and encoding are NULL, options 0. */
    xmlTextReaderPtr reader = xmlReaderForMemory((const char *)Data, bufSize, NULL, NULL, 0);
    if (reader == NULL) {
        /* Nothing to do */
        xmlCleanupParser();
        return 0;
    }

    /* Iterate through nodes; for each node attempt to read its string content. */
    int readRet;
    while ((readRet = xmlTextReaderRead(reader)) == 1) {
        xmlChar *s = xmlTextReaderReadString(reader);
        if (s != NULL) {
            /* Free the returned string using libxml's allocator */
            xmlFree(s);
        }
    }

    /* Cleanup reader and libxml state */
    xmlFreeTextReader(reader);
    xmlCleanupParser();

    return 0;
}