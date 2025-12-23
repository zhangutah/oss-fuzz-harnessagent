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
// //testUndeclEntInContent(void) {
// //    const char xml[] = "<!DOCTYPE doc SYSTEM 'my.dtd'><doc>&undecl;</doc>";
// //    const char content[] = "<doc>&undecl;</doc>";
// //    xmlDocPtr doc;
// //    xmlNodePtr root, list;
// //    int options = XML_PARSE_NOENT | XML_PARSE_NOERROR;
// //    int err = 0;
// //    int res;
// //
// //    /* Parsing the document succeeds because of the external DTD. */
// //    doc = xmlReadDoc(BAD_CAST xml, NULL, NULL, options);
// //    root = xmlDocGetRootElement(doc);
// //
// //    /* Parsing content fails. */
// //
// //    res = xmlParseInNodeContext(root, content, sizeof(content) - 1, options,
// //                                &list);
// //    if (res != XML_ERR_UNDECLARED_ENTITY || list != NULL) {
// //        fprintf(stderr, "Wrong result from xmlParseInNodeContext\n");
// //        err = 1;
// //    }
// //    xmlFreeNodeList(list);
// //
// //#ifdef LIBXML_SAX1_ENABLED
// //    xmlSetStructuredErrorFunc(NULL, ignoreError);
// //    res = xmlParseBalancedChunkMemory(doc, NULL, NULL, 0, BAD_CAST content,
// //                                      &list);
// //    if (res != XML_ERR_UNDECLARED_ENTITY || list != NULL) {
// //        fprintf(stderr, "Wrong result from xmlParseBalancedChunkMemory\n");
// //        err = 1;
// //    }
// //    xmlFreeNodeList(list);
// //    xmlSetStructuredErrorFunc(NULL, NULL);
// //#endif /* LIBXML_SAX1_ENABLED */
// //
// //    xmlFreeDoc(doc);
// //
// //    return err;
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlParserErrors xmlParseInNodeContext(xmlNode * node, const char * data, int datalen, int options, xmlNode ** lst);
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
#include <string.h>

/* Include the parser header found in the project */
#include "/src/libxml2/include/libxml/parser.h"

/* BAD_CAST is usually provided by libxml2, but define defensively */
#ifndef BAD_CAST
#define BAD_CAST (xmlChar *)
#endif

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /*
         * Initialize the libxml2 parser library once.
         * xmlInitParser is idempotent.
         */
        xmlInitParser();
        inited = 1;
    }

    /* Clamp Size to int to match xmlParseInNodeContext signature */
    int datalen = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a minimal document with a root node to provide a node context. */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL)
        return 0;

    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }
    /* Attach root to the document */
    xmlDocSetRootElement(doc, root);

    /* Prepare pointer for returned node list */
    xmlNode *lst = NULL;

    /* Call the function under test with no special options (0). */
    /* Cast Data to const char* as expected by the API. */
    (void)xmlParseInNodeContext(root, (const char *)Data, datalen, 0, &lst);

    /* Free any node list produced by the parser */
    if (lst != NULL)
        xmlFreeNodeList(lst);

    /* Free the document (frees the root node as well) */
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here because it is global and may
       be undesirable between fuzzing corpus runs. */

    return 0;
}