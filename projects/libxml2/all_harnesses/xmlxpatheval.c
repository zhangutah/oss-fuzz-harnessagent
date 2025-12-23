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
// // xmlXPathObject *
// //xmlXPathNodeEval(xmlNode *node, const xmlChar *str, xmlXPathContext *ctx) {
// //    if (str == NULL)
// //        return(NULL);
// //    if (xmlXPathSetContextNode(node, ctx) < 0)
// //        return(NULL);
// //    return(xmlXPathEval(str, ctx));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlXPathObject * xmlXPathEval(const xmlChar * str, xmlXPathContext * ctx);
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

/* Prefer project absolute headers as returned by the codebase search.
   If these paths do not exist in the build environment, replace them
   with the usual system includes <libxml/parser.h> and <libxml/xpath.h>. */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/* libxml uses xmlChar for strings */
#ifndef BAD_CAST
#define BAD_CAST (xmlChar *)
#endif

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the parser (idempotent after first call). */
    xmlInitParser();

    /* Split the input into two parts:
       - first part: XML document bytes
       - second part: XPath expression bytes
       If the input is very small, use a default small XML document. */
    size_t split = Size / 2;
    if (split == 0) split = 1; /* ensure some bytes for the XML part */
    size_t xml_len = split;
    size_t xpath_len = (Size > split) ? (Size - split) : 0;

    xmlDocPtr doc = NULL;
    /* Try to parse the first part as an XML document */
    if (xml_len > 0) {
        /* xmlReadMemory expects a (const char *) buffer and an int length */
        char *xml_buf = (char *)malloc(xml_len + 1);
        if (xml_buf == NULL)
            return 0;
        memcpy(xml_buf, Data, xml_len);
        xml_buf[xml_len] = '\0';
        /* Use len as int (xmlReadMemory takes int for size) */
        doc = xmlReadMemory(xml_buf, (int)xml_len, NULL, NULL, 0);
        free(xml_buf);
    }

    /* If parsing failed, create a minimal document to have a valid context */
    if (doc == NULL) {
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc != NULL) {
            xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
            if (root != NULL)
                xmlDocSetRootElement(doc, root);
        } else {
            /* If even that fails, abort this input */
            return 0;
        }
    }

    /* Prepare the XPath expression from the remaining bytes.
       If there's no remaining input, use an empty expression. */
    const xmlChar *expr = NULL;
    char *expr_buf = NULL;
    if (xpath_len > 0) {
        expr_buf = (char *)malloc(xpath_len + 1);
        if (expr_buf == NULL) {
            xmlFreeDoc(doc);
            return 0;
        }
        memcpy(expr_buf, Data + split, xpath_len);
        expr_buf[xpath_len] = '\0';
        expr = (const xmlChar *)expr_buf;
    } else {
        /* zero-length expression */
        expr_buf = (char *)malloc(1);
        if (expr_buf == NULL) {
            xmlFreeDoc(doc);
            return 0;
        }
        expr_buf[0] = '\0';
        expr = (const xmlChar *)expr_buf;
    }

    /* Create an XPath evaluation context for the document */
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (ctx != NULL) {
        /* Evaluate the expression; this is the target function under test */
        xmlXPathObjectPtr result = xmlXPathEval(expr, ctx);

        /* Free result if returned */
        if (result != NULL)
            xmlXPathFreeObject(result);

        /* Clean up context */
        xmlXPathFreeContext(ctx);
    }

    /* Free resources */
    free(expr_buf);
    xmlFreeDoc(doc);

    /* Do NOT call xmlCleanupParser() here because libFuzzer may call this
       function repeatedly and xmlCleanupParser would destruct global state.
       Leave cleanup to the process exit. */

    return 0;
}
