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
// //xmlValidateDocumentInternal(xmlParserCtxtPtr ctxt, xmlValidCtxtPtr vctxt,
// //                            xmlDocPtr doc) {
// //    int ret;
// //    xmlNodePtr root;
// //
// //    if (doc == NULL)
// //        return(0);
// //    if ((doc->intSubset == NULL) && (doc->extSubset == NULL)) {
// //        xmlErrValid(vctxt, XML_DTD_NO_DTD,
// //	            "no DTD found!\n", NULL);
// //	return(0);
// //    }
// //
// //    if ((doc->intSubset != NULL) && ((doc->intSubset->SystemID != NULL) ||
// //	(doc->intSubset->ExternalID != NULL)) && (doc->extSubset == NULL)) {
// //	xmlChar *sysID = NULL;
// //
// //	if (doc->intSubset->SystemID != NULL) {
// //            int res;
// //
// //            res = xmlBuildURISafe(doc->intSubset->SystemID, doc->URL, &sysID);
// //            if (res < 0) {
// //                xmlVErrMemory(vctxt);
// //                return 0;
// //            } else if (res != 0) {
// //                xmlErrValid(vctxt, XML_DTD_LOAD_ERROR,
// //			"Could not build URI for external subset \"%s\"\n",
// //			(const char *) doc->intSubset->SystemID);
// //		return 0;
// //	    }
// //	}
// //
// //        if (ctxt != NULL) {
// //            xmlParserInputPtr input;
// //
// //            input = xmlLoadResource(ctxt, (const char *) sysID,
// //                    (const char *) doc->intSubset->ExternalID,
// //                    XML_RESOURCE_DTD);
// //            if (input == NULL) {
// //                xmlFree(sysID);
// //                return 0;
// //            }
// //
// //            doc->extSubset = xmlCtxtParseDtd(ctxt, input,
// //                                             doc->intSubset->ExternalID,
// //                                             sysID);
// //        } else {
// //            doc->extSubset = xmlParseDTD(doc->intSubset->ExternalID, sysID);
// //        }
// //
// //	if (sysID != NULL)
// //	    xmlFree(sysID);
// //        if (doc->extSubset == NULL) {
// //	    if (doc->intSubset->SystemID != NULL) {
// //		xmlErrValid(vctxt, XML_DTD_LOAD_ERROR,
// //		       "Could not load the external subset \"%s\"\n",
// //		       (const char *) doc->intSubset->SystemID);
// //	    } else {
// //		xmlErrValid(vctxt, XML_DTD_LOAD_ERROR,
// //		       "Could not load the external subset \"%s\"\n",
// //		       (const char *) doc->intSubset->ExternalID);
// //	    }
// //	    return(0);
// //	}
// //    }
// //
// //    if (doc->ids != NULL) {
// //          xmlFreeIDTable(doc->ids);
// //          doc->ids = NULL;
// //    }
// //    if (doc->refs != NULL) {
// //          xmlFreeRefTable(doc->refs);
// //          doc->refs = NULL;
// //    }
// //    ret = xmlValidateDtdFinal(vctxt, doc);
// //    if (!xmlValidateRoot(vctxt, doc)) return(0);
// //
// //    root = xmlDocGetRootElement(doc);
// //    ret &= xmlValidateElement(vctxt, doc, root);
// //    ret &= xmlValidateDocumentFinal(vctxt, doc);
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
//     int xmlValidateElement(xmlValidCtxt * ctxt, xmlDoc * doc, xmlNode * elem);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: int xmlValidateElement(xmlValidCtxt *ctxt, xmlDoc *doc, xmlNode *elem);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver:
// - Parses the input bytes as an XML document using xmlReadMemory.
// - Creates a validation context with xmlNewValidCtxt.
// - Calls xmlValidateElement() on the document root.
// - Cleans up allocated resources.

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

/* libxml2 public headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive checks */
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the parser library (safe to call multiple times). */
    xmlInitParser();

    /* xmlReadMemory expects an int size; guard against very large sizes. */
    int parseSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Parse the input bytes as an XML document (no URL, no encoding, no extra options). */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, parseSize, NULL, NULL, 0);

    /* Allocate a validation context. */
    xmlValidCtxt *vctxt = xmlNewValidCtxt();

    /* If we couldn't allocate a validation context, just clean up and return. */
    if (vctxt == NULL) {
        if (doc)
            xmlFreeDoc(doc);
        /* Cleanup global parser state */
        xmlCleanupParser();
        return 0;
    }

    /* Optionally disable structured error output to avoid noisy stderr output during fuzzing.
       The following sets no structured error function (NULL) which is the default. */
    xmlSetStructuredErrorFunc(NULL, NULL);

    /* Get the document root (may be NULL if parsing failed). */
    xmlNodePtr root = doc ? xmlDocGetRootElement(doc) : NULL;

    /* Call the target function under test. Provide the validation context, the doc and the root node. */
    /* Note: xmlValidateElement handles NULL arguments in some cases, but we still guard above. */
    (void)xmlValidateElement(vctxt, doc, root);

    /* Free validation context and document (if any). */
    xmlFreeValidCtxt(vctxt);
    if (doc)
        xmlFreeDoc(doc);

    /* Cleanup parser global state (okay to call frequently in a fuzzing harness). */
    xmlCleanupParser();

    return 0;
}