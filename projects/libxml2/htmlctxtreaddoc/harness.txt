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
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * htmlCtxtReadDoc(xmlParserCtxt * ctxt, const xmlChar * cur, const char * URL, const char * encoding, int options);
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

/* Ensure HTML APIs are exposed from the header */
#define LIBXML_HTML_ENABLED 1
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlversion.h"

/*
 * Fuzzer entry point for libFuzzer / LLVMFuzzerTestOneInput.
 *
 * This driver creates a parser context, makes a nul-terminated copy of the
 * fuzzer input, and calls htmlCtxtReadDoc() with the input as the document
 * buffer. It frees all resources afterwards.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Create a nul-terminated copy of the input for libxml2 functions */
    unsigned char *buf = (unsigned char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0'; /* ensure termination */

    /* Initialize the library (safe to call multiple times) */
    xmlInitParser();

    /* Create a parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        free(buf);
        xmlCleanupParser();
        return 0;
    }

    /* Optionally suppress global error printing by redirecting errors.
       Uncomment and provide a handler if desired:
       xmlSetGenericErrorFunc(NULL, myErrorHandler);
    */

    /* Call the target function.
       - cur: the buffer (xmlChar == unsigned char)
       - URL: NULL (no base URL)
       - encoding: NULL (auto-detect)
       - options: 0 (default)
    */
    xmlDocPtr doc = htmlCtxtReadDoc(ctxt, (const xmlChar *)buf, NULL, NULL, 0);

    /* Free the resulting document (if any) */
    if (doc)
        xmlFreeDoc(doc);

    /* Free parser context */
    xmlFreeParserCtxt(ctxt);

    /* Free our buffer */
    free(buf);

    /* Cleanup library state (note: this may not be desirable if multiple
       fuzz iterations rely on persistent state; libFuzzer runs this many times
       in one process 	6 calling xmlCleanupParser here is generally safe but
       can be omitted if you prefer to do it once at process teardown). */
    xmlCleanupParser();

    return 0;
}
