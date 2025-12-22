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
// //htmlNodeDumpFile(FILE *out, xmlDoc *doc, xmlNode *cur) {
// //    htmlNodeDumpFileFormat(out, doc, cur, NULL, 1);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int htmlNodeDumpFileFormat(FILE * out, xmlDoc * doc, xmlNode * cur, const char * encoding, int format);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libxml/HTMLtree.h>
#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 Fuzzer entry point for:
   int htmlNodeDumpFileFormat(FILE * out, xmlDoc * doc, xmlNode * cur,
                              const char * encoding, int format);
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser state */
    xmlInitParser();

    /* Create a temporary file to receive output */
    FILE *out = tmpfile();
    if (out == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Parse the input bytes as HTML into an xmlDoc */
    /* Use recover/noerror/nowarning to make parsing robust for fuzzing */
    int options = HTML_PARSE_RECOVER | HTML_PARSE_NOERROR | HTML_PARSE_NOWARNING;
    /* htmlReadMemory expects an int size; guard against very large sizes */
    int parseSize = (Size > INT_MAX) ? INT_MAX : (int)Size;
    xmlDocPtr doc = htmlReadMemory((const char *)Data, parseSize, NULL, NULL, options);

    /* Prepare arguments for htmlNodeDumpFileFormat */
    const char *encoding = NULL;
    int format = 0;
    /* Choose format bit (0 or 1) based on last byte to vary behavior */
    format = (Size > 0) ? (Data[Size - 1] & 1) : 0;

    /* Sometimes provide a (safe) encoding string derived from input to exercise code paths */
    char encbuf[64];
    if (Size > 1 && (Data[0] & 1)) {
        size_t n = (Size - 1 < sizeof(encbuf) - 1) ? (Size - 1) : (sizeof(encbuf) - 1);
        /* Make sure encoding string is printable and null-terminated */
        for (size_t i = 0; i < n; ++i) {
            unsigned char c = Data[1 + i];
            encbuf[i] = (c >= 32 && c < 127) ? (char)c : 'x';
        }
        encbuf[n] = '\0';
        encoding = encbuf;
    }

    if (doc != NULL) {
        /* Pick the document's root node as the node to dump if available */
        xmlNodePtr root = xmlDocGetRootElement(doc);
        /* Call the target function under test */
        (void)htmlNodeDumpFileFormat(out, doc, root, encoding, format);

        /* Free the parsed document */
        xmlFreeDoc(doc);
    } else {
        /* If parsing failed, still attempt calling the function with NULL doc/node
           to exercise error handling paths. Many implementations expect valid doc,
           but we keep this to broaden coverage. */
        (void)htmlNodeDumpFileFormat(out, NULL, NULL, encoding, format);
    }

    /* Clean up the file and parser state */
    fflush(out);
    fclose(out);

    xmlCleanupParser();

    return 0;
}
