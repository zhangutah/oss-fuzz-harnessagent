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
//     int xmlXPathCmpNodes(xmlNode * node1, xmlNode * node2);
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

/* Prefer the project header path returned by analysis; fallback to standard include */
#include "/src/libxml2/include/libxml/xpath.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

/*
 Fuzzer entry point for libFuzzer:
 Fuzzes: int xmlXPathCmpNodes(xmlNode * node1, xmlNode * node2);
 Strategy:
  - Split the input bytes into two parts.
  - Parse each part as an XML document using xmlReadMemory().
  - Obtain the document root for each parsed document (if parsing fails, create a temporary node).
  - Call xmlXPathCmpNodes(root1, root2).
  - Clean up allocated documents/nodes.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0)
        return 0;

    /* Initialize the parser (safe to call multiple times). */
    xmlInitParser();

    xmlDocPtr doc1 = NULL, doc2 = NULL;
    xmlNodePtr node1 = NULL, node2 = NULL;
    int created1 = 0, created2 = 0;

    /* If input is small, just create two simple nodes to compare. */
    if (Size < 2) {
        node1 = xmlNewNode(NULL, BAD_CAST "a");
        node2 = xmlNewNode(NULL, BAD_CAST "b");
        created1 = created2 = 1;
    } else {
        /* Split input into two parts */
        size_t mid = Size / 2;
        const char *buf1 = (const char *)Data;
        const char *buf2 = (const char *)(Data + mid);
        int size1 = (int)mid;
        int size2 = (int)(Size - mid);

        /*
         xmlReadMemory accepts arbitrary bytes and a size, so this is safe with binary data.
         Use NULL for URL and encoding and 0 for options for permissive parsing.
        */
        doc1 = xmlReadMemory(buf1, size1, "fuzz1.xml", NULL, 0);
        doc2 = xmlReadMemory(buf2, size2, "fuzz2.xml", NULL, 0);

        if (doc1)
            node1 = xmlDocGetRootElement(doc1);
        if (doc2)
            node2 = xmlDocGetRootElement(doc2);

        /* If parsing failed for either, create a temporary node. */
        if (!node1) {
            node1 = xmlNewNode(NULL, BAD_CAST "fuzzNode1");
            created1 = 1;
        }
        if (!node2) {
            node2 = xmlNewNode(NULL, BAD_CAST "fuzzNode2");
            created2 = 1;
        }
    }

    /* Call the target function. Keep the result in a volatile to avoid optimizer elision. */
    volatile int result = 0;
    result = xmlXPathCmpNodes(node1, node2);

    /* Cleanup */
    if (doc1)
        xmlFreeDoc(doc1);
    if (doc2)
        xmlFreeDoc(doc2);

    if (created1 && node1)
        xmlFreeNode(node1);
    if (created2 && node2)
        xmlFreeNode(node2);

    /* Note: Do not call xmlCleanupParser() here; calling it repeatedly during fuzzing
       can degrade performance or unset global state used by subsequent runs. */

    (void)result; /* silence unused volatile warnings in some toolchains */
    return 0;
}