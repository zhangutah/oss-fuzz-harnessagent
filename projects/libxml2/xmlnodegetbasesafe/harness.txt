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
// // static void
// //xmlXIncludeBaseFixup(xmlXIncludeCtxtPtr ctxt, xmlNodePtr cur, xmlNodePtr copy,
// //                     const xmlChar *targetBase) {
// //    xmlChar *base = NULL;
// //    xmlChar *relBase = NULL;
// //    xmlNs ns;
// //    int res;
// //
// //    if (cur->type != XML_ELEMENT_NODE)
// //        return;
// //
// //    if (xmlNodeGetBaseSafe(cur->doc, cur, &base) < 0)
// //        xmlXIncludeErrMemory(ctxt);
// //
// //    if ((base != NULL) && !xmlStrEqual(base, targetBase)) {
// //        if ((xmlStrlen(base) > XML_MAX_URI_LENGTH) ||
// //            (xmlStrlen(targetBase) > XML_MAX_URI_LENGTH)) {
// //            relBase = xmlStrdup(base);
// //            if (relBase == NULL) {
// //                xmlXIncludeErrMemory(ctxt);
// //                goto done;
// //            }
// //        } else if (xmlBuildRelativeURISafe(base, targetBase, &relBase) < 0) {
// //            xmlXIncludeErrMemory(ctxt);
// //            goto done;
// //        }
// //        if (relBase == NULL) {
// //            xmlXIncludeErr(ctxt, cur,
// //                    XML_XINCLUDE_HREF_URI,
// //                    "Building relative URI failed: %s\n",
// //                    base);
// //            goto done;
// //        }
// //
// //        /*
// //         * If the new base doesn't contain a slash, it can be omitted.
// //         */
// //        if (xmlStrchr(relBase, '/') != NULL) {
// //            res = xmlNodeSetBase(copy, relBase);
// //            if (res < 0)
// //                xmlXIncludeErrMemory(ctxt);
// //            goto done;
// //        }
// //    }
// //
// //    /*
// //     * Delete existing xml:base if bases are equal
// //     */
// //    memset(&ns, 0, sizeof(ns));
// //    ns.href = XML_XML_NAMESPACE;
// //    xmlUnsetNsProp(copy, &ns, BAD_CAST "base");
// //
// //done:
// //    xmlFree(base);
// //    xmlFree(relBase);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlNodeGetBaseSafe(const xmlDoc * doc, const xmlNode * cur, xmlChar ** baseOut);
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

/* Use project headers (absolute paths discovered in repository) */
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzzer entry point expected by libFuzzer / LLVMFuzzer:
 extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int libxml_initialized = 0;

    /* Initialize libxml once per process to set up global state. */
    if (!libxml_initialized) {
        xmlInitParser();
        libxml_initialized = 1;
    }

    /* Basic sanity checks on input. */
    if (Data == NULL || Size == 0)
        return 0;

    /* xmlReadMemory expects an int size; cap to INT_MAX to avoid negative cast. */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Parse the fuzz input as an XML/HTML document. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, len, NULL, NULL, 0);
    if (doc == NULL)
        return 0;

    /* We'll try a few sensible callers to exercise xmlNodeGetBaseSafe. */
    xmlChar *base = NULL;
    xmlNodePtr root = xmlDocGetRootElement(doc);

    /* 1) Call with both doc and root provided. */
    if (root != NULL) {
        int rc = xmlNodeGetBaseSafe((const xmlDoc *)doc, (const xmlNode *)root, &base);
        if (base != NULL) {
            xmlFree(base);
            base = NULL;
        }
        (void)rc; /* ignore return value; we only care about crashes/memory issues */
    } else {
        /* No root: call with doc and cur == NULL to exercise document-level handling. */
        int rc = xmlNodeGetBaseSafe((const xmlDoc *)doc, NULL, &base);
        if (base != NULL) {
            xmlFree(base);
            base = NULL;
        }
        (void)rc;
    }

    /* 2) Call with doc==NULL but cur provided (if we have a node). */
    if (root != NULL) {
        int rc = xmlNodeGetBaseSafe(NULL, (const xmlNode *)root, &base);
        if (base != NULL) {
            xmlFree(base);
            base = NULL;
        }
        (void)rc;
    }

    /* 3) Another variation: pass the first child of the root if available. */
    if (root != NULL && root->children != NULL) {
        int rc = xmlNodeGetBaseSafe((const xmlDoc *)doc, (const xmlNode *)root->children, &base);
        if (base != NULL) {
            xmlFree(base);
            base = NULL;
        }
        (void)rc;
    }

    /* Clean up the parsed document. */
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here: libFuzzer runs many iterations in the same process,
       calling xmlCleanupParser() could interfere with subsequent iterations if called too early.
       If a global teardown is needed, it can be registered separately. */

    return 0;
}
