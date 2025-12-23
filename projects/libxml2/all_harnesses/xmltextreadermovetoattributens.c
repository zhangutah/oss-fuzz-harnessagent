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
//     int xmlTextReaderMoveToAttributeNs(xmlTextReader * reader, const xmlChar * localName, const xmlChar * namespaceURI);
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

/* Use the project-provided header for libxml2's reader API. */
#include "/src/libxml2/include/libxml/xmlreader.h"
#include "/src/libxml2/include/libxml/parser.h"

/*
 Fuzzer entry point for libFuzzer:
 Fuzzes: int xmlTextReaderMoveToAttributeNs(xmlTextReader * reader,
                                            const xmlChar * localName,
                                            const xmlChar * namespaceURI);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int libxml_inited = 0;
    if (!libxml_inited) {
        /* Initialize libxml2 library once. */
        xmlInitParser();
        LIBXML_TEST_VERSION
        libxml_inited = 1;
    }

    /* Create an xmlTextReader from the input bytes. Treat the whole input as XML content. */
    xmlTextReaderPtr reader = NULL;
    if (Size > 0) {
        /* xmlReaderForMemory expects a (const char*) buffer */
        reader = xmlReaderForMemory((const char *)Data, (int)Size, NULL, NULL, 0);
    } else {
        /* For empty input, create a reader from an empty string. */
        reader = xmlReaderForMemory("", 0, NULL, NULL, 0);
    }

    /* Prepare two NUL-terminated strings for localName and namespaceURI derived from the input.
       We'll split the input in two parts. If Size == 0 both strings will be empty. */
    char *localName = NULL;
    char *namespaceURI = NULL;
    size_t len1 = 0, len2 = 0;

    if (Size == 0) {
        len1 = 0;
        len2 = 0;
    } else {
        len1 = Size / 2;
        len2 = Size - len1;
    }

    localName = (char *)malloc(len1 + 1);
    namespaceURI = (char *)malloc(len2 + 1);
    if (!localName || !namespaceURI) {
        free(localName);
        free(namespaceURI);
        if (reader) xmlFreeTextReader(reader);
        return 0;
    }

    if (len1 > 0) memcpy(localName, Data, len1);
    localName[len1] = '\0';
    if (len2 > 0) memcpy(namespaceURI, Data + len1, len2);
    namespaceURI[len2] = '\0';

    /* If reader creation failed, still call the target with a NULL reader is invalid,
       so just skip the actual call in that case. */
    if (reader) {
        /* Call the function under test. We cast to xmlChar* (unsigned char*) as required. */
        (void)xmlTextReaderMoveToAttributeNs(reader,
                                             (const xmlChar *)localName,
                                             (const xmlChar *)namespaceURI);

        /* Clean up the reader after use. */
        xmlFreeTextReader(reader);
    }

    free(localName);
    free(namespaceURI);

    /* Do not call xmlCleanupParser() here: it is global and expensive; omit to keep fuzzer performance. */
    return 0;
}
