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
// // xmlTextReader *
// //xmlReaderForDoc(const xmlChar * cur, const char *URL, const char *encoding,
// //                int options)
// //{
// //    int len;
// //
// //    if (cur == NULL)
// //        return (NULL);
// //    len = xmlStrlen(cur);
// //
// //    return (xmlReaderForMemory
// //            ((const char *) cur, len, URL, encoding, options));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlTextReader * xmlReaderForMemory(const char * buffer, int size, const char * URL, const char * encoding, int options);
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

/* Use project absolute headers found for the symbol */
#include "/src/libxml2/include/libxml/xmlreader.h"
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic sanity check */
    if (Data == NULL || Size == 0)
        return 0;

    /* Ensure libxml is initialized once. Calling xmlInitParser multiple times is harmless
       but we try to avoid repeated initialization for performance. */
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        /* Optionally enable some defaults if desired:
           xmlSubstituteEntitiesDefault(1);
        */
        initialized = 1;
    }

    /* xmlReaderForMemory expects an int size parameter. Cap to INT_MAX to avoid overflow. */
    int int_size = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a reader from the raw input buffer. URL and encoding set to NULL, options = 0. */
    xmlTextReaderPtr reader = xmlReaderForMemory((const char *)Data, int_size, NULL, NULL, 0);
    if (reader == NULL)
        return 0;

    /* Walk the document to exercise the reader. */
    while (xmlTextReaderRead(reader) == 1) {
        /* Touch some reader APIs to increase code coverage. */
        const xmlChar *name = xmlTextReaderConstName(reader);
        const xmlChar *value = xmlTextReaderConstValue(reader);
        (void)name;
        (void)value;

        /* Optionally query node type or depth to exercise more code paths */
        (void)xmlTextReaderNodeType(reader);
        (void)xmlTextReaderDepth(reader);
    }

    /* Clean up the reader (this also frees the associated input buffer). */
    xmlFreeTextReader(reader);

    /* Do not call xmlCleanupParser() here  allowing the process lifetime to manage final cleanup
       is usually fine for fuzzers. */

    return 0;
}
