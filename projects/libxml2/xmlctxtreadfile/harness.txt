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
//     xmlDoc * xmlCtxtReadFile(xmlParserCtxt * ctxt, const char * filename, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Use absolute project headers discovered for the target symbols */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Fuzzer entry point. This driver writes the fuzzer input to a temporary
 * file and then calls xmlCtxtReadFile(xmlParserCtxt *ctxt, const char *filename, const char *encoding, int options).
 *
 * The driver takes care to allocate and free an xml parser context and to
 * free the resulting document (if any). The temporary file is removed before
 * returning.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Create a parser context */
    xmlInitParser(); /* initialize libxml2 (harmless if called repeatedly) */
    xmlParserCtxt *ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Create a temporary file to hold the input bytes */
    char tmpname[] = "/tmp/libxml2_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Write all data to the temporary file (handle partial writes) */
    ssize_t total_written = 0;
    const uint8_t *ptr = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, ptr + total_written, remaining);
        if (w <= 0) break;
        total_written += w;
        remaining -= (size_t)w;
    }

    /* Ensure data is flushed before the parser opens the file */
    fsync(fd);
    close(fd);

    /* Call the target API: read the file into an xmlDoc via the parser context */
    /* encoding = NULL, options = 0 (no special parser options) */
    xmlDoc *doc = xmlCtxtReadFile(ctxt, tmpname, NULL, 0);

    /* Clean up the document if parsing succeeded */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Remove the temporary file */
    unlink(tmpname);

    /* Free parser context and cleanup libxml2 */
    xmlFreeParserCtxt(ctxt);
    xmlCleanupParser();

    return 0;
}
