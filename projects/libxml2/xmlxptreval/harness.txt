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
// //xmlXIncludeLoadDoc(xmlXIncludeCtxtPtr ctxt, xmlXIncludeRefPtr ref) {
// //    xmlXIncludeDocPtr cache;
// //    xmlDocPtr doc;
// //    const xmlChar *url = ref->URI;
// //    const xmlChar *fragment = ref->fragment;
// //    int i = 0;
// //    int ret = -1;
// //    int cacheNr;
// //#ifdef LIBXML_XPTR_ENABLED
// //    int saveFlags;
// //#endif
// //
// //    /*
// //     * Handling of references to the local document are done
// //     * directly through ctxt->doc.
// //     */
// //    if ((url[0] == 0) || (url[0] == '#') ||
// //	((ctxt->doc != NULL) && (xmlStrEqual(url, ctxt->doc->URL)))) {
// //	doc = ctxt->doc;
// //        goto loaded;
// //    }
// //
// //    /*
// //     * Prevent reloading the document twice.
// //     */
// //    for (i = 0; i < ctxt->urlNr; i++) {
// //	if (xmlStrEqual(url, ctxt->urlTab[i].url)) {
// //            if (ctxt->urlTab[i].expanding) {
// //                xmlXIncludeErr(ctxt, ref->elem, XML_XINCLUDE_RECURSION,
// //                               "inclusion loop detected\n", NULL);
// //                goto error;
// //            }
// //	    doc = ctxt->urlTab[i].doc;
// //            if (doc == NULL)
// //                goto error;
// //	    goto loaded;
// //	}
// //    }
// //
// //    /*
// //     * Load it.
// //     */
// //#ifdef LIBXML_XPTR_ENABLED
// //    /*
// //     * If this is an XPointer evaluation, we want to assure that
// //     * all entities have been resolved prior to processing the
// //     * referenced document
// //     */
// //    saveFlags = ctxt->parseFlags;
// //    if (fragment != NULL) {	/* if this is an XPointer eval */
// //	ctxt->parseFlags |= XML_PARSE_NOENT;
// //    }
// //#endif
// //
// //    doc = xmlXIncludeParseFile(ctxt, (const char *)url);
// //#ifdef LIBXML_XPTR_ENABLED
// //    ctxt->parseFlags = saveFlags;
// //#endif
// //
// //    /* Also cache NULL docs */
// //    if (ctxt->urlNr >= ctxt->urlMax) {
// //        xmlXIncludeDoc *tmp;
// //        int newSize;
// //
// //        newSize = xmlGrowCapacity(ctxt->urlMax, sizeof(tmp[0]),
// //                                  8, XML_MAX_ITEMS);
// //        if (newSize < 0) {
// //            xmlXIncludeErrMemory(ctxt);
// //            xmlFreeDoc(doc);
// //            goto error;
// //        }
// //        tmp = xmlRealloc(ctxt->urlTab, newSize * sizeof(tmp[0]));
// //        if (tmp == NULL) {
// //            xmlXIncludeErrMemory(ctxt);
// //            xmlFreeDoc(doc);
// //            goto error;
// //        }
// //        ctxt->urlMax = newSize;
// //        ctxt->urlTab = tmp;
// //    }
// //    cache = &ctxt->urlTab[ctxt->urlNr];
// //    cache->doc = doc;
// //    cache->url = xmlStrdup(url);
// //    if (cache->url == NULL) {
// //        xmlXIncludeErrMemory(ctxt);
// //        xmlFreeDoc(doc);
// //        goto error;
// //    }
// //    cache->expanding = 0;
// //    cacheNr = ctxt->urlNr++;
// //
// //    if (doc == NULL)
// //        goto error;
// //    /*
// //     * It's possible that the requested URL has been mapped to a
// //     * completely different location (e.g. through a catalog entry).
// //     * To check for this, we compare the URL with that of the doc
// //     * and change it if they disagree (bug 146988).
// //     */
// //    if ((doc->URL != NULL) && (!xmlStrEqual(url, doc->URL)))
// //        url = doc->URL;
// //
// //    /*
// //     * Make sure we have all entities fixed up
// //     */
// //    xmlXIncludeMergeEntities(ctxt, ctxt->doc, doc);
// //
// //    /*
// //     * We don't need the DTD anymore, free up space
// //    if (doc->intSubset != NULL) {
// //	xmlUnlinkNode((xmlNodePtr) doc->intSubset);
// //	xmlFreeNode((xmlNodePtr) doc->intSubset);
// //	doc->intSubset = NULL;
// //    }
// //    if (doc->extSubset != NULL) {
// //	xmlUnlinkNode((xmlNodePtr) doc->extSubset);
// //	xmlFreeNode((xmlNodePtr) doc->extSubset);
// //	doc->extSubset = NULL;
// //    }
// //     */
// //    cache->expanding = 1;
// //    xmlXIncludeRecurseDoc(ctxt, doc);
// //    /* urlTab might be reallocated. */
// //    cache = &ctxt->urlTab[cacheNr];
// //    cache->expanding = 0;
// //
// //loaded:
// //    if (fragment == NULL) {
// //        xmlNodePtr root;
// //
// //        root = xmlDocGetRootElement(doc);
// //        if (root == NULL) {
// //            xmlXIncludeErr(ctxt, ref->elem, XML_ERR_INTERNAL_ERROR,
// //                           "document without root\n", NULL);
// //            goto error;
// //        }
// //
// //        ref->inc = xmlDocCopyNode(root, ctxt->doc, 1);
// //        if (ref->inc == NULL) {
// //            xmlXIncludeErrMemory(ctxt);
// //            goto error;
// //        }
// //
// //        if (ref->base != NULL)
// //            xmlXIncludeBaseFixup(ctxt, root, ref->inc, ref->base);
// //    }
// //#ifdef LIBXML_XPTR_ENABLED
// //    else {
// //	/*
// //	 * Computes the XPointer expression and make a copy used
// //	 * as the replacement copy.
// //	 */
// //	xmlXPathObjectPtr xptr;
// //	xmlNodeSetPtr set;
// //
// //        if (ctxt->isStream && doc == ctxt->doc) {
// //	    xmlXIncludeErr(ctxt, ref->elem, XML_XINCLUDE_XPTR_FAILED,
// //			   "XPointer expressions not allowed in streaming"
// //                           " mode\n", NULL);
// //            goto error;
// //        }
// //
// //        if (ctxt->xpctxt == NULL) {
// //            ctxt->xpctxt = xmlXPathNewContext(doc);
// //            if (ctxt->xpctxt == NULL) {
// //                xmlXIncludeErrMemory(ctxt);
// //                goto error;
// //            }
// //            if (ctxt->errorHandler != NULL)
// //                xmlXPathSetErrorHandler(ctxt->xpctxt, ctxt->errorHandler,
// //                                        ctxt->errorCtxt);
// //#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// //            ctxt->xpctxt->opLimit = 100000;
// //#endif
// //        } else {
// //            ctxt->xpctxt->doc = doc;
// //        }
// //	xptr = xmlXPtrEval(fragment, ctxt->xpctxt);
// //	if (ctxt->xpctxt->lastError.code != XML_ERR_OK) {
// //            if (ctxt->xpctxt->lastError.code == XML_ERR_NO_MEMORY)
// //                xmlXIncludeErrMemory(ctxt);
// //            else
// //                xmlXIncludeErr(ctxt, ref->elem, XML_XINCLUDE_XPTR_FAILED,
// //                               "XPointer evaluation failed: #%s\n",
// //                               fragment);
// //            goto error;
// //	}
// //        if (xptr == NULL)
// //            goto done;
// //	switch (xptr->type) {
// //	    case XPATH_UNDEFINED:
// //	    case XPATH_BOOLEAN:
// //	    case XPATH_NUMBER:
// //	    case XPATH_STRING:
// //	    case XPATH_USERS:
// //	    case XPATH_XSLT_TREE:
// //		xmlXIncludeErr(ctxt, ref->elem, XML_XINCLUDE_XPTR_RESULT,
// //			       "XPointer is not a range: #%s\n",
// //			       fragment);
// //                xmlXPathFreeObject(xptr);
// //                goto error;
// //	    case XPATH_NODESET:
// //                break;
// //
// //	}
// //	set = xptr->nodesetval;
// //	if (set != NULL) {
// //	    for (i = 0;i < set->nodeNr;i++) {
// //		if (set->nodeTab[i] == NULL) /* shouldn't happen */
// //		    continue;
// //		switch (set->nodeTab[i]->type) {
// //		    case XML_ELEMENT_NODE:
// //		    case XML_TEXT_NODE:
// //		    case XML_CDATA_SECTION_NODE:
// //		    case XML_ENTITY_REF_NODE:
// //		    case XML_ENTITY_NODE:
// //		    case XML_PI_NODE:
// //		    case XML_COMMENT_NODE:
// //		    case XML_DOCUMENT_NODE:
// //		    case XML_HTML_DOCUMENT_NODE:
// //			continue;
// //
// //		    case XML_ATTRIBUTE_NODE:
// //			xmlXIncludeErr(ctxt, ref->elem,
// //			               XML_XINCLUDE_XPTR_RESULT,
// //				       "XPointer selects an attribute: #%s\n",
// //				       fragment);
// //			goto xptr_error;
// //		    case XML_NAMESPACE_DECL:
// //			xmlXIncludeErr(ctxt, ref->elem,
// //			               XML_XINCLUDE_XPTR_RESULT,
// //				       "XPointer selects a namespace: #%s\n",
// //				       fragment);
// //			goto xptr_error;
// //		    case XML_DOCUMENT_TYPE_NODE:
// //		    case XML_DOCUMENT_FRAG_NODE:
// //		    case XML_NOTATION_NODE:
// //		    case XML_DTD_NODE:
// //		    case XML_ELEMENT_DECL:
// //		    case XML_ATTRIBUTE_DECL:
// //		    case XML_ENTITY_DECL:
// //		    case XML_XINCLUDE_START:
// //		    case XML_XINCLUDE_END:
// //                        /* shouldn't happen */
// //			xmlXIncludeErr(ctxt, ref->elem,
// //			               XML_XINCLUDE_XPTR_RESULT,
// //				   "XPointer selects unexpected nodes: #%s\n",
// //				       fragment);
// //			goto xptr_error;
// //		}
// //	    }
// //	}
// //        ref->inc = xmlXIncludeCopyXPointer(ctxt, xptr, ref->base);
// //xptr_error:
// //        xmlXPathFreeObject(xptr);
// //    }
// //
// //done:
// //#endif
// //
// //    ret = 0;
// //
// //error:
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
//     xmlXPathObject * xmlXPtrEval(const xmlChar * str, xmlXPathContext * ctx);
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

/* Absolute includes from the project (prefer absolute path as requested) */
#include "/src/libxml2/include/libxml/xpointer.h"
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/* Fuzzer entry point expected by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Convert input to a NUL-terminated xmlChar string */
    unsigned char *buf = (unsigned char *)malloc(Size + 1);
    if (buf == NULL) return 0;
    if (Size > 0 && Data != NULL) memcpy(buf, Data, Size);
    buf[Size] = '\0';
    const xmlChar *xptrExpr = (const xmlChar *)buf;

    /* Initialize parser state (xmlXPtrEval calls xmlInitParser() internally,
       but calling it here is harmless and ensures initialization). */
    xmlInitParser();

    /* Create a minimal document for the XPath context to reference.
       Using a real doc increases the amount of code paths exercised. */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");

    /* Create an XPath context bound to the doc. */
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (ctx == NULL) {
        if (doc) xmlFreeDoc(doc);
        free(buf);
        return 0;
    }

    /* Mark this as an XPointer context to enable xpointer-specific behavior. */
    ctx->xptr = 1;

    /* Call the target function under test. */
    xmlXPathObjectPtr res = xmlXPtrEval(xptrExpr, ctx);

    /* Clean up returned object and context/doc. */
    if (res != NULL) xmlXPathFreeObject(res);
    xmlXPathFreeContext(ctx);
    if (doc) xmlFreeDoc(doc);

    /* Free local buffer and cleanup parser globals (optional). */
    free(buf);
    /* Do not call xmlCleanupParser() if the fuzzer runtime expects global state to persist
       across multiple calls; it's commented out to be safer. Uncomment if desired. */
    /* xmlCleanupParser(); */

    return 0;
}