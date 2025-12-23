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
// // static xmlChar *
// //xmlSchemaNormalizeValue(xmlSchemaTypePtr type,
// //			const xmlChar *value)
// //{
// //    switch (xmlSchemaGetWhiteSpaceFacetValue(type)) {
// //	case XML_SCHEMA_WHITESPACE_COLLAPSE:
// //	    return (xmlSchemaCollapseString(value));
// //	case XML_SCHEMA_WHITESPACE_REPLACE:
// //	    return (xmlSchemaWhiteSpaceReplace(value));
// //	default:
// //	    return (NULL);
// //    }
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlChar * xmlSchemaCollapseString(const xmlChar * value);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     xmlChar * xmlSchemaCollapseString(const xmlChar * value);
//
// Builds a fuzzing entry point that turns the arbitrary input bytes into
// a NUL-terminated xmlChar string, calls xmlSchemaCollapseString and frees
// any allocated resources.
//
// Note: This file includes the project header using the absolute path
// returned by the codebase. Adjust includes as needed for your build system.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Include libxml2 headers (absolute paths from the repository). */
#include "/src/libxml2/include/libxml/xmlschemastypes.h"
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/parser.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Protect against null Data pointer per libFuzzer contract (Data may be NULL when Size==0). */
    if (Size == 0) {
        /* Pass an empty string */
        const xmlChar empty = 0;
        xmlChar *res = xmlSchemaCollapseString(&empty);
        if (res != NULL) {
            /* xmlSchemaCollapseString returns a newly allocated xmlChar* in most cases */
            xmlFree(res);
        }
        return 0;
    }

    /* Limit allocation size to something reasonable to avoid OOM on malicious inputs.
       This is optional and can be adjusted or removed. */
    const size_t MAX_ALLOC = 10 * 1024 * 1024; /* 10 MB */
    size_t useSize = Size;
    if (useSize > MAX_ALLOC) useSize = MAX_ALLOC;

    /* Allocate a buffer and ensure it is NUL-terminated as xmlSchemaCollapseString expects a C string. */
    xmlChar *buf = (xmlChar *)malloc(useSize + 1);
    if (buf == NULL) return 0;

    memcpy(buf, Data, useSize);
    buf[useSize] = 0; /* NUL terminate */

    /* Optionally initialize the parser/library if needed by other functions.
       xmlSchemaCollapseString itself should not require parser initialization, but
       calling xmlInitParser is cheap and safe. */
    xmlInitParser();

    /* Call the function under test. */
    xmlChar *ret = xmlSchemaCollapseString((const xmlChar *)buf);

    /* Free any returned value as the implementation returns allocated memory on change. */
    if (ret != NULL) {
        xmlFree(ret);
    }

    free(buf);

    /* No global state to clean up for each input. */
    return 0;
}
