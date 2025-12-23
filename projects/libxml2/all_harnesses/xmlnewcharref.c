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
//     xmlNode * xmlNewCharRef(xmlDoc * doc, const xmlChar * name);
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

#include <libxml/parser.h>
#include <libxml/tree.h>

#ifndef MAX_FUZZ_INPUT
#define MAX_FUZZ_INPUT (1 << 20) // 1 MiB cap for safety
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Cap the size to avoid huge allocations from malformed inputs
    if (Size > MAX_FUZZ_INPUT) {
        Size = MAX_FUZZ_INPUT;
    }

    // Initialize the libxml2 library (safe to call multiple times)
    xmlInitParser();

    // Create a simple XML document version string
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL) {
        xmlCleanupParser();
        return 0;
    }

    // Allocate a null-terminated buffer for the name (xmlChar is unsigned char)
    xmlChar *name = (xmlChar *)malloc(Size + 1);
    if (name == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    memcpy(name, Data, Size);
    name[Size] = '\0';

    // Call the target function under test
    xmlNodePtr node = xmlNewCharRef(doc, (const xmlChar *)name);

    // If a node was created, free it to avoid leaks
    if (node != NULL) {
        // xmlUnlinkNode is unnecessary for an unattached node,
        // xmlFreeNode will free the node and its children.
        xmlFreeNode(node);
    }

    // Clean up
    free(name);
    xmlFreeDoc(doc);
    // Optionally cleanup global parser state
    xmlCleanupParser();

    return 0;
}
