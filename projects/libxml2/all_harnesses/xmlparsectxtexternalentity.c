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
// // int
// //xmlParseExternalEntity(xmlDoc *doc, xmlSAXHandler *sax, void *user_data,
// //	  int depth, const xmlChar *URL, const xmlChar *ID, xmlNode **list) {
// //    xmlParserCtxtPtr ctxt;
// //    int ret;
// //
// //    if (list != NULL)
// //        *list = NULL;
// //
// //    if (doc == NULL)
// //        return(XML_ERR_ARGUMENT);
// //
// //    ctxt = xmlNewSAXParserCtxt(sax, user_data);
// //    if (ctxt == NULL)
// //        return(XML_ERR_NO_MEMORY);
// //
// //    ctxt->depth = depth;
// //    ctxt->myDoc = doc;
// //    ret = xmlParseCtxtExternalEntity(ctxt, URL, ID, list);
// //
// //    xmlFreeParserCtxt(ctxt);
// //    return(ret);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlParseCtxtExternalEntity(xmlParserCtxt * ctx, const xmlChar * URL, const xmlChar * ID, xmlNode ** lst);
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

/* Absolute include as discovered in the project */
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* initialize libxml only once */
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Create a parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Split input into URL and ID parts.
       Simple strategy: first half -> URL, second half -> ID
    */
    size_t url_len = Size / 2;
    size_t id_len = Size - url_len;

    /* Allocate and null-terminate buffers */
    xmlChar *url = (xmlChar *)malloc(url_len + 1);
    if (url == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    memcpy(url, Data, url_len);
    url[url_len] = '\0';

    xmlChar *id = NULL;
    if (id_len > 0) {
        id = (xmlChar *)malloc(id_len + 1);
        if (id == NULL) {
            free(url);
            xmlFreeParserCtxt(ctxt);
            return 0;
        }
        memcpy(id, Data + url_len, id_len);
        id[id_len] = '\0';
    }

    /* Prepare output list pointer */
    xmlNodePtr lst = NULL;
    xmlNodePtr *plst = &lst;

    /* Call the target function. Cast to const xmlChar* as required. */
    /* The call may create nodes in 'lst' or return an error code. */
    (void) xmlParseCtxtExternalEntity(ctxt, (const xmlChar *)url,
                                      (const xmlChar *)id, plst);

    /* If nodes were returned, free them to avoid leaks.
       xmlFreeNodeList is provided by libxml2 for freeing node lists.
    */
    if (lst != NULL) {
        xmlFreeNodeList(lst);
        lst = NULL;
    }

    /* Cleanup */
    free(url);
    if (id) free(id);
    xmlFreeParserCtxt(ctxt);

    /* Do not call xmlCleanupParser() here as the fuzzer may call the
       harness many times; cleanup at process exit is fine.
    */

    return 0;
}