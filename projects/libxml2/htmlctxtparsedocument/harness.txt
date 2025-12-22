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
// // xmlDoc *
// //htmlReadFd(int fd, const char *url, const char *encoding, int options)
// //{
// //    htmlParserCtxtPtr ctxt;
// //    xmlParserInputPtr input;
// //    htmlDocPtr doc = NULL;
// //
// //    ctxt = htmlNewParserCtxt();
// //    if (ctxt == NULL)
// //        return(NULL);
// //
// //    htmlCtxtUseOptions(ctxt, options);
// //
// //    input = xmlCtxtNewInputFromFd(ctxt, url, fd, encoding, 0);
// //
// //    if (input != NULL)
// //        doc = htmlCtxtParseDocument(ctxt, input);
// //
// //    htmlFreeParserCtxt(ctxt);
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
//     xmlDoc * htmlCtxtParseDocument(htmlParserCtxt * ctxt, xmlParserInput * input);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlDoc * htmlCtxtParseDocument(htmlParserCtxt * ctxt, xmlParserInput * input);
// Fuzzer entry point: LLVMFuzzerTestOneInput
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Simple fuzz harness:
 * - Initialize the parser library (xmlInitParser).
 * - Create an HTML parser context.
 * - Create an xmlParserInput from the provided memory buffer.
 * - Call htmlCtxtParseDocument(ctxt, input).
 * - Free the resulting document and parser context.
 *
 * Notes:
 * - htmlCtxtParseDocument will free the pushed input stream internally in
 *   its implementation, so the harness does not free 'input'.
 * - xmlInitParser() is safe to call repeatedly; if desired it can be
 *   guarded to run once. Keeping it simple here.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser (idempotent) */
    xmlInitParser();

    /* Create an HTML parser context */
    htmlParserCtxtPtr ctxt = htmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Create an xmlParserInput from the fuzzing buffer.
     * xmlNewInputFromMemory will allocate an input that htmlCtxtParseDocument
     * may take ownership of (and free internally). Passing NULL for URL
     * and 0 for flags.
     */
    xmlParserInputPtr input = xmlNewInputFromMemory(NULL, (const void *)Data, Size, 0);
    if (input == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Call the target function under test */
    xmlDocPtr doc = htmlCtxtParseDocument(ctxt, input);

    /* Free any produced document */
    if (doc != NULL)
        xmlFreeDoc(doc);

    /* Free the parser context */
    xmlFreeParserCtxt(ctxt);

    /* Note: do not call xmlCleanupParser() here as the fuzzer may call this
     * function many times; cleanup is typically done at program exit.
     */

    return 0;
}
