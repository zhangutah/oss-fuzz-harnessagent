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
//     xmlChar * xmlTextReaderGetAttributeNs(xmlTextReader * reader, const xmlChar * localName, const xmlChar * namespaceURI);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   xmlChar * xmlTextReaderGetAttributeNs(xmlTextReader * reader,
//                                         const xmlChar * localName,
//                                         const xmlChar * namespaceURI);
//
// Build environment note: this driver includes the project's headers using absolute
// paths returned by the codebase. Adjust include paths if you compile outside the
// project container.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Use the project headers (absolute paths as returned by the workspace tools) */
#include "/src/libxml2/include/libxml/xmlreader.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point expected by LLVM libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size < 1)
        return 0;

    /* Initialize parser (safe to call multiple times in some environments) */
    xmlInitParser();

    /*
     * Strategy: split the input buffer into three parts:
     *  - xml_buf: the XML document text to feed to xmlReaderForMemory
     *  - localName: the local attribute name to look up
     *  - namespaceURI: the namespace URI to look up
     *
     * If any part is empty, we still pass a zero-length C string for it.
     */

    size_t xml_size = (Size * 2) / 3;
    if (xml_size == 0)
        xml_size = 1; /* ensure at least 1 byte for the XML buffer if possible */

    if (xml_size > Size)
        xml_size = Size;

    size_t rem = Size - xml_size;
    size_t name_len = rem / 2;
    size_t ns_len = rem - name_len;

    /* Allocate and null-terminate the three parts */
    char *xml_buf = (char *)malloc(xml_size + 1);
    char *name_buf = (char *)malloc(name_len + 1);
    char *ns_buf = (char *)malloc(ns_len + 1);

    if (!xml_buf || !name_buf || !ns_buf) {
        free(xml_buf);
        free(name_buf);
        free(ns_buf);
        xmlCleanupParser();
        return 0;
    }

    /* Copy data into parts */
    memcpy(xml_buf, Data, xml_size);
    xml_buf[xml_size] = '\0';

    if (name_len > 0)
        memcpy(name_buf, Data + xml_size, name_len);
    name_buf[name_len] = '\0';

    if (ns_len > 0)
        memcpy(ns_buf, Data + xml_size + name_len, ns_len);
    ns_buf[ns_len] = '\0';

    /* Create an xmlTextReader from the in-memory XML buffer */
    xmlTextReaderPtr reader = xmlReaderForMemory(xml_buf, (int)xml_size, NULL, NULL, 0);
    if (reader == NULL) {
        /* Could not create a reader -- cleanup and return */
        free(xml_buf);
        free(name_buf);
        free(ns_buf);
        xmlCleanupParser();
        return 0;
    }

    /*
     * Advance the reader until we reach an element node (or EOF).
     * xmlTextReaderGetAttributeNs requires reader->node to be an element node
     * and reader->curnode to be NULL (i.e., not positioned on an attribute).
     */
    int ret;
    int steps = 0;
    while ((ret = xmlTextReaderRead(reader)) == 1 && steps < 50) {
        steps++;
        int nodeType = xmlTextReaderNodeType(reader);
        /* XML_READER_TYPE_ELEMENT is a macro defined in xmlreader.h */
        if (nodeType == XML_READER_TYPE_ELEMENT) {
            /* Call the target API with the provided local name and namespace */
            xmlChar *res = xmlTextReaderGetAttributeNs(reader,
                                                       (const xmlChar *)name_buf,
                                                       (const xmlChar *)ns_buf);
            if (res != NULL) {
                /* The returned string must be freed by the caller */
                xmlFree(res);
            }
            /* We exercised the API; break out. Further looping is optional. */
            break;
        }
    }

    /* Free the reader and allocated buffers */
    xmlFreeTextReader(reader);
    free(xml_buf);
    free(name_buf);
    free(ns_buf);

    /* Clean up parser state */
    xmlCleanupParser();

    return 0;
}