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
//     xmlNode * xmlStringLenGetNodeList(const xmlDoc * doc, const xmlChar * value, int len);
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

/* Include libxml2 headers - using project absolute paths found in the workspace */
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzz driver for:
   xmlNode * xmlStringLenGetNodeList(const xmlDoc * doc, const xmlChar * value, int len);

 The fuzzer entry point:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize libxml2 parser (safe to call multiple times) */
    xmlInitParser();

    /* Protect against extremely large inputs from the fuzzer */
    const size_t MAX_COPY = 65536; /* 64KB */
    size_t copy_len = Size < MAX_COPY ? Size : MAX_COPY;

    /* Allocate a buffer and ensure it is NUL-terminated for xmlChar usage */
    unsigned char *buf = (unsigned char *)malloc(copy_len + 1);
    if (!buf) {
        xmlCleanupParser();
        return 0;
    }
    if (copy_len > 0)
        memcpy(buf, Data, copy_len);
    buf[copy_len] = '\0';

    /* Create a minimal xmlDoc context (some libxml2 functions expect a doc pointer) */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        free(buf);
        xmlCleanupParser();
        return 0;
    }

    /* Derive the 'len' parameter from the input bytes when possible to exercise
       different code paths (including negative values). If insufficient bytes,
       use the copy length. */
    int len;
    if (Size >= 4) {
        uint32_t v = 0;
        memcpy(&v, Data, sizeof(v));
        len = (int)v;
    } else {
        /* use a value that can be negative or positive */
        len = (int)copy_len;
    }

    /* Call the target function. The value argument is of type const xmlChar* */
    xmlNodePtr node_list = xmlStringLenGetNodeList(doc, (const xmlChar *)buf, len);

    /* Free any nodes returned by the function (if any). */
    if (node_list != NULL) {
        xmlFreeNodeList(node_list);
    }

    /* Cleanup doc and local resources */
    xmlFreeDoc(doc);
    free(buf);

    /* Cleanup libxml2 parser globals (ok to call repeatedly in fuzzing harness) */
    xmlCleanupParser();

    return 0;
}