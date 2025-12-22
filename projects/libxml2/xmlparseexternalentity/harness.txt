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
//     int xmlParseExternalEntity(xmlDoc * doc, xmlSAXHandler * sax, void * user_data, int depth, const xmlChar * URL, const xmlChar * ID, xmlNode ** lst);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmlParseExternalEntity(xmlDoc * doc, xmlSAXHandler * sax, void * user_data,
//                              int depth, const xmlChar * URL, const xmlChar * ID,
//                              xmlNode ** lst);
// Fuzzer entry point: LLVMFuzzerTestOneInput

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Use the project header discovered for the symbol */
#include "/src/libxml2/include/libxml/parser.h"

/* Cap strings to avoid very large allocations */
#define MAX_STR_LEN 4096

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Initialize libxml (safe even if called multiple times) */
    xmlInitParser();

    /* Create a simple empty document to pass as 'doc' */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Prepare URL and ID from the input buffer.
       Split the fuzz input roughly in half for URL and ID.
       If Size is 0, pass NULL for both. */
    xmlChar *url_buf = NULL;
    xmlChar *id_buf = NULL;
    xmlNodePtr lst = NULL; /* receiver for returned node list pointer */

    if (Size > 0) {
        size_t half = Size / 2;
        size_t len1 = half;
        size_t len2 = Size - half;

        /* Cap lengths to MAX_STR_LEN to avoid huge allocations */
        if (len1 > MAX_STR_LEN) len1 = MAX_STR_LEN;
        if (len2 > MAX_STR_LEN) len2 = MAX_STR_LEN;

        if (len1 > 0) {
            url_buf = (xmlChar *)malloc(len1 + 1);
            if (url_buf) {
                memcpy(url_buf, Data, len1);
                url_buf[len1] = '\0';
            }
        }
        if (len2 > 0) {
            id_buf = (xmlChar *)malloc(len2 + 1);
            if (id_buf) {
                memcpy(id_buf, Data + half, len2);
                id_buf[len2] = '\0';
            }
        }
    }

    /* Choose a small depth derived from the input to explore variations */
    int depth = 0;
    if (Size > 0) {
        depth = Data[0] & 0x0F; /* 0..15 */
    }

    /* Call the target function. Use NULL for sax and user_data (common usage). */
    /* Guard the call in case libxml expects non-NULL doc (we provided one). */
    (void)xmlParseExternalEntity(doc, /*doc*/ NULL, /*sax*/ NULL, /*user_data*/ depth,
                                 url_buf, id_buf, &lst);

    /* Clean up allocated memory and libxml structures */
    if (url_buf) free(url_buf);
    if (id_buf) free(id_buf);

    /* Free the document which should free associated nodes */
    xmlFreeDoc(doc);

    /* Cleanup parser state (no-op if other fuzz iterations rely on it, but safe) */
    xmlCleanupParser();

    return 0;
}