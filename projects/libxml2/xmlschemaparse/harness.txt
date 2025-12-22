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
// //processSchema(const char *xsdFile, const char *xmlFile, FILE *out) {
// //    xmlSchemaPtr schema;
// //    xmlSchemaParserCtxtPtr pctxt;
// //
// //    /* Max allocations. */
// //    xmlFuzzWriteInt(out, 0, 4);
// //
// //    fuzzRecorderInit(out);
// //
// //    pctxt = xmlSchemaNewParserCtxt(xsdFile);
// //    xmlSchemaSetParserStructuredErrors(pctxt, xmlFuzzSErrorFunc, NULL);
// //    xmlSchemaSetResourceLoader(pctxt, fuzzResourceRecorder, NULL);
// //    schema = xmlSchemaParse(pctxt);
// //    xmlSchemaFreeParserCtxt(pctxt);
// //
// //    if (schema != NULL) {
// //        xmlSchemaValidCtxtPtr vctxt;
// //        xmlParserCtxtPtr ctxt;
// //        xmlDocPtr doc;
// //
// //        ctxt = xmlNewParserCtxt();
// //        xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
// //        xmlCtxtSetResourceLoader(ctxt, fuzzResourceRecorder, NULL);
// //        doc = xmlCtxtReadFile(ctxt, xmlFile, NULL, XML_PARSE_NOENT);
// //        xmlFreeParserCtxt(ctxt);
// //
// //        vctxt = xmlSchemaNewValidCtxt(schema);
// //        xmlSchemaSetValidStructuredErrors(vctxt, xmlFuzzSErrorFunc, NULL);
// //        xmlSchemaValidateDoc(vctxt, doc);
// //        xmlSchemaFreeValidCtxt(vctxt);
// //
// //        xmlFreeDoc(doc);
// //        xmlSchemaFree(schema);
// //    }
// //
// //    fuzzRecorderWrite(xsdFile);
// //    fuzzRecorderWrite(xmlFile);
// //    fuzzRecorderCleanup();
// //
// //    return(0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlSchema * xmlSchemaParse(xmlSchemaParserCtxt * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include "/src/libxml2/include/libxml/xmlschemas.h"
#include "/src/libxml2/include/libxml/parser.h"

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

/*
 * Fuzzer entry point for fuzzing:
 *     xmlSchema * xmlSchemaParse(xmlSchemaParserCtxt * ctxt);
 *
 * This harness builds a memory-based schema parser context from the input
 * bytes and calls xmlSchemaParse(), then frees resources.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser state (safe to call multiple times). */
    xmlInitParser();

    /* xmlSchemaNewMemParserCtxt takes an int size; cap to INT_MAX to avoid overflow. */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a parser context from the provided input bytes. */
    xmlSchemaParserCtxtPtr pctxt = xmlSchemaNewMemParserCtxt((const char *)Data, len);
    if (pctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Parse the schema (this is the target function). */
    xmlSchemaPtr schema = xmlSchemaParse(pctxt);

    /* Free the returned schema if any. */
    if (schema != NULL)
        xmlSchemaFree(schema);

    /* Free the parser context. */
    xmlSchemaFreeParserCtxt(pctxt);

    /* Cleanup global parser state. */
    xmlCleanupParser();

    return 0;
}