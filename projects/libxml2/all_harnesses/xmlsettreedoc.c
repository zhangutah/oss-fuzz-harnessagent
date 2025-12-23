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
// // xmlDoc *
// //xmlCopyDoc(xmlDoc *doc, int recursive) {
// //    xmlDocPtr ret;
// //
// //    if (doc == NULL) return(NULL);
// //    ret = xmlNewDoc(doc->version);
// //    if (ret == NULL) return(NULL);
// //    ret->type = doc->type;
// //    if (doc->name != NULL) {
// //        ret->name = xmlMemStrdup(doc->name);
// //        if (ret->name == NULL)
// //            goto error;
// //    }
// //    if (doc->encoding != NULL) {
// //        ret->encoding = xmlStrdup(doc->encoding);
// //        if (ret->encoding == NULL)
// //            goto error;
// //    }
// //    if (doc->URL != NULL) {
// //        ret->URL = xmlStrdup(doc->URL);
// //        if (ret->URL == NULL)
// //            goto error;
// //    }
// //    ret->charset = doc->charset;
// //    ret->compression = doc->compression;
// //    ret->standalone = doc->standalone;
// //    if (!recursive) return(ret);
// //
// //    ret->last = NULL;
// //    ret->children = NULL;
// //    if (doc->intSubset != NULL) {
// //        ret->intSubset = xmlCopyDtd(doc->intSubset);
// //	if (ret->intSubset == NULL)
// //            goto error;
// //        /* Can't fail on DTD */
// //	xmlSetTreeDoc((xmlNodePtr)ret->intSubset, ret);
// //    }
// //    if (doc->oldNs != NULL) {
// //        ret->oldNs = xmlCopyNamespaceList(doc->oldNs);
// //        if (ret->oldNs == NULL)
// //            goto error;
// //    }
// //    if (doc->children != NULL) {
// //	xmlNodePtr tmp;
// //
// //	ret->children = xmlStaticCopyNodeList(doc->children, ret,
// //		                               (xmlNodePtr)ret);
// //        if (ret->children == NULL)
// //            goto error;
// //	ret->last = NULL;
// //	tmp = ret->children;
// //	while (tmp != NULL) {
// //	    if (tmp->next == NULL)
// //	        ret->last = tmp;
// //	    tmp = tmp->next;
// //	}
// //    }
// //    return(ret);
// //
// //error:
// //    xmlFreeDoc(ret);
// //    return(NULL);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlSetTreeDoc(xmlNode * tree, xmlDoc * doc);
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

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 Fuzz driver for:
     int xmlSetTreeDoc(xmlNode * tree, xmlDoc * doc);

 The fuzzer entry point:
     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Minimal checks */
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser once per process (safe to call multiple times) */
    static int parser_inited = 0;
    if (!parser_inited) {
        xmlInitParser();
        parser_inited = 1;
    }

    /* Parse the input into an xmlDoc. Use recover and nonet to limit side effects. */
    xmlDocPtr docA = xmlReadMemory((const char *)Data,
                                  (int)Size,
                                  "fuzz.xml",    /* base URL (for errors) */
                                  NULL,          /* encoding: let parser detect */
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (docA == NULL)
        return 0;

    /* Get a starting node (root) */
    xmlNodePtr node = xmlDocGetRootElement(docA);
    if (node == NULL) {
        xmlFreeDoc(docA);
        return 0;
    }

    /* Walk the tree deterministically using bytes from the input to choose path.
       This tries to reach different nodes for different inputs. */
    xmlNodePtr cur = node;
    for (size_t i = 0; i < Size; ++i) {
        if (cur == NULL)
            break;
        uint8_t b = Data[i];
        if ((b & 1) && cur->children) {
            cur = cur->children;
        } else if (cur->next) {
            cur = cur->next;
        } else if (cur->parent && cur->parent->next) {
            /* try a sibling of parent to diversify */
            cur = cur->parent->next;
        } else {
            break;
        }
    }

    /* Create a fresh document to pass as the 'doc' argument.
       Using xmlNewDoc keeps this allocation minimal and valid. */
    xmlDocPtr docB = xmlNewDoc(BAD_CAST "1.0");
    if (docB == NULL) {
        xmlFreeDoc(docA);
        return 0;
    }

    /* Call the target function with the selected node and the new doc.
       Also try a couple of additional, simple variations to increase coverage. */
    (void)xmlSetTreeDoc(cur, docB);    /* primary invocation */
    (void)xmlSetTreeDoc(node, NULL);   /* pass NULL doc */
    (void)xmlSetTreeDoc(NULL, docB);   /* pass NULL tree (should be handled) */

    /* Clean up.
       Free the parsed documents. Order shouldn't matter for fuzzing here;
       libxml2 internals will free structures allocated for each doc. */
    xmlFreeDoc(docA);
    xmlFreeDoc(docB);

    /* Do not call xmlCleanupParser() here: it is global and may interfere with
       other fuzzing harness state when running multiple inputs. */

    return 0;
}
