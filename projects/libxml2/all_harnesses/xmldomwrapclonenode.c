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
//     int xmlDOMWrapCloneNode(xmlDOMWrapCtxt * ctxt, xmlDoc * sourceDoc, xmlNode * node, xmlNode ** clonedNode, xmlDoc * destDoc, xmlNode * destParent, int deep, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Use project headers found by the workspace search */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzzer entry point for:
 int xmlDOMWrapCloneNode(xmlDOMWrapCtxt * ctxt,
                         xmlDoc * sourceDoc,
                         xmlNode * node,
                         xmlNode ** clonedNode,
                         xmlDoc * destDoc,
                         xmlNode * destParent,
                         int deep,
                         int options);
 
 This driver:
 - Parses the fuzzer input as an XML document using xmlReadMemory.
 - Picks the document root element (if any).
 - Creates a new empty destination document.
 - Calls xmlDOMWrapCloneNode(NULL, sourceDoc, root, &cloned, destDoc, NULL, deep, options).
 - Frees any allocated resources.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* Initialize the libxml2 library once. */
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Parse the input buffer as an XML document.
       Use recover and nonet options to avoid network/entity fetches. */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET;
    xmlDocPtr sourceDoc = xmlReadMemory((const char *)Data, (int)Size,
                                       "fuzz-input.xml", /* URL (for error messages) */
                                       NULL,             /* encoding */
                                       parseOptions);
    if (sourceDoc == NULL) {
        /* Not a valid XML document, nothing to do. */
        return 0;
    }

    /* Get the root element. xmlDOMWrapCloneNode currently only supports element nodes. */
    xmlNodePtr root = xmlDocGetRootElement(sourceDoc);
    if (root == NULL) {
        xmlFreeDoc(sourceDoc);
        return 0;
    }

    /* Create a destination document to receive the cloned node. */
    xmlDocPtr destDoc = xmlNewDoc((const xmlChar *)"1.0");
    if (destDoc == NULL) {
        xmlFreeDoc(sourceDoc);
        return 0;
    }

    /* Attempt to clone the root element. We pass NULL as the ctxt pointer (context)
       because it's optional in many uses; the function should handle a NULL ctxt
       or not reference it immediately. Use deep=1 to clone recursively. */
    xmlNodePtr cloned = NULL;
    int deep = 1;
    int options = 0; /* no special options */

    /* Call the function under test. */
    (void)xmlDOMWrapCloneNode(NULL, sourceDoc, root, &cloned, destDoc, NULL, deep, options);

    /* If a clone was returned, free it. xmlFreeNode will free the node subtree.
       It's safe even if the clone references destDoc. */
    if (cloned != NULL) {
        xmlFreeNode(cloned);
        cloned = NULL;
    }

    /* Free documents and return. */
    xmlFreeDoc(destDoc);
    xmlFreeDoc(sourceDoc);

    /* Do not call xmlCleanupParser() here: that can break repeated fuzzer calls in the same process. */
    return 0;
}
