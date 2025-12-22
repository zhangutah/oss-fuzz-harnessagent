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
// // static xmlAttrPtr
// //xmlSAX2AttributeNs(xmlParserCtxtPtr ctxt,
// //                   const xmlChar * localname,
// //                   const xmlChar * prefix,
// //		   const xmlChar * value,
// //		   const xmlChar * valueend)
// //{
// //    xmlAttrPtr ret;
// //    xmlNsPtr namespace = NULL;
// //    xmlChar *dup = NULL;
// //
// //    /*
// //     * Note: if prefix == NULL, the attribute is not in the default namespace
// //     */
// //    if (prefix != NULL) {
// //	namespace = xmlParserNsLookupSax(ctxt, prefix);
// //	if ((namespace == NULL) && (xmlStrEqual(prefix, BAD_CAST "xml"))) {
// //            int res;
// //
// //	    res = xmlSearchNsSafe(ctxt->node, prefix, &namespace);
// //            if (res < 0)
// //                xmlSAX2ErrMemory(ctxt);
// //	}
// //    }
// //
// //    /*
// //     * allocate the node
// //     */
// //    if (ctxt->freeAttrs != NULL) {
// //        ret = ctxt->freeAttrs;
// //	ctxt->freeAttrs = ret->next;
// //	ctxt->freeAttrsNr--;
// //    } else {
// //        ret = xmlMalloc(sizeof(*ret));
// //        if (ret == NULL) {
// //            xmlSAX2ErrMemory(ctxt);
// //            return(NULL);
// //        }
// //    }
// //
// //    memset(ret, 0, sizeof(xmlAttr));
// //    ret->type = XML_ATTRIBUTE_NODE;
// //
// //    /*
// //     * xmlParseBalancedChunkMemoryRecover had a bug that could result in
// //     * a mismatch between ctxt->node->doc and ctxt->myDoc. We use
// //     * ctxt->node->doc here, but we should somehow make sure that the
// //     * document pointers match.
// //     */
// //
// //    /* assert(ctxt->node->doc == ctxt->myDoc); */
// //
// //    ret->parent = ctxt->node;
// //    ret->doc = ctxt->node->doc;
// //    ret->ns = namespace;
// //
// //    if (ctxt->dictNames) {
// //        ret->name = localname;
// //    } else {
// //        ret->name = xmlStrdup(localname);
// //        if (ret->name == NULL)
// //            xmlSAX2ErrMemory(ctxt);
// //    }
// //
// //    if ((xmlRegisterCallbacks) && (xmlRegisterNodeDefaultValue))
// //        xmlRegisterNodeDefaultValue((xmlNodePtr)ret);
// //
// //    if ((ctxt->replaceEntities == 0) && (!ctxt->html)) {
// //	xmlNodePtr tmp;
// //
// //	/*
// //	 * We know that if there is an entity reference, then
// //	 * the string has been dup'ed and terminates with 0
// //	 * otherwise with ' or "
// //	 */
// //	if (*valueend != 0) {
// //	    tmp = xmlSAX2TextNode(ctxt, ret->doc, value, valueend - value);
// //	    ret->children = tmp;
// //	    ret->last = tmp;
// //	    if (tmp != NULL) {
// //		tmp->parent = (xmlNodePtr) ret;
// //	    }
// //	} else if (valueend > value) {
// //            if (xmlNodeParseAttValue(ret->doc, ret, value, valueend - value,
// //                                     NULL) < 0)
// //                xmlSAX2ErrMemory(ctxt);
// //	}
// //    } else if (value != NULL) {
// //	xmlNodePtr tmp;
// //
// //	tmp = xmlSAX2TextNode(ctxt, ret->doc, value, valueend - value);
// //	ret->children = tmp;
// //	ret->last = tmp;
// //	if (tmp != NULL) {
// //	    tmp->parent = (xmlNodePtr) ret;
// //	}
// //    }
// //
// //#ifdef LIBXML_VALID_ENABLED
// //    if ((!ctxt->html) && ctxt->validate && ctxt->wellFormed &&
// //        ctxt->myDoc && ctxt->myDoc->intSubset) {
// //	/*
// //	 * If we don't substitute entities, the validation should be
// //	 * done on a value with replaced entities anyway.
// //	 */
// //        if (!ctxt->replaceEntities) {
// //	    dup = xmlSAX2DecodeAttrEntities(ctxt, value, valueend);
// //	    if (dup == NULL) {
// //	        if (*valueend == 0) {
// //		    ctxt->valid &= xmlValidateOneAttribute(&ctxt->vctxt,
// //				    ctxt->myDoc, ctxt->node, ret, value);
// //		} else {
// //		    /*
// //		     * That should already be normalized.
// //		     * cheaper to finally allocate here than duplicate
// //		     * entry points in the full validation code
// //		     */
// //		    dup = xmlStrndup(value, valueend - value);
// //                    if (dup == NULL)
// //                        xmlSAX2ErrMemory(ctxt);
// //
// //		    ctxt->valid &= xmlValidateOneAttribute(&ctxt->vctxt,
// //				    ctxt->myDoc, ctxt->node, ret, dup);
// //		}
// //	    } else {
// //	        /*
// //		 * dup now contains a string of the flattened attribute
// //		 * content with entities substituted. Check if we need to
// //		 * apply an extra layer of normalization.
// //		 * It need to be done twice ... it's an extra burden related
// //		 * to the ability to keep references in attributes
// //		 */
// //		if (ctxt->attsSpecial != NULL) {
// //		    xmlChar *nvalnorm;
// //		    xmlChar fn[50];
// //		    xmlChar *fullname;
// //
// //		    fullname = xmlBuildQName(localname, prefix, fn, 50);
// //                    if (fullname == NULL) {
// //                        xmlSAX2ErrMemory(ctxt);
// //                    } else {
// //			ctxt->vctxt.valid = 1;
// //		        nvalnorm = xmlValidCtxtNormalizeAttributeValue(
// //			                 &ctxt->vctxt, ctxt->myDoc,
// //					 ctxt->node, fullname, dup);
// //			if (ctxt->vctxt.valid != 1)
// //			    ctxt->valid = 0;
// //
// //			if ((fullname != fn) && (fullname != localname))
// //			    xmlFree(fullname);
// //			if (nvalnorm != NULL) {
// //			    xmlFree(dup);
// //			    dup = nvalnorm;
// //			}
// //		    }
// //		}
// //
// //		ctxt->valid &= xmlValidateOneAttribute(&ctxt->vctxt,
// //			        ctxt->myDoc, ctxt->node, ret, dup);
// //	    }
// //	} else {
// //	    /*
// //	     * if entities already have been substituted, then
// //	     * the attribute as passed is already normalized
// //	     */
// //	    dup = xmlStrndup(value, valueend - value);
// //            if (dup == NULL)
// //                xmlSAX2ErrMemory(ctxt);
// //
// //            /*
// //             * When replacing entities, make sure that IDs in
// //             * entities aren't registered. This also shouldn't be
// //             * done when entities aren't replaced, but this would
// //             * require to rework IDREF checks.
// //             */
// //            if (ctxt->input->entity != NULL)
// //                ctxt->vctxt.flags |= XML_VCTXT_IN_ENTITY;
// //
// //	    ctxt->valid &= xmlValidateOneAttribute(&ctxt->vctxt,
// //	                             ctxt->myDoc, ctxt->node, ret, dup);
// //
// //            ctxt->vctxt.flags &= ~XML_VCTXT_IN_ENTITY;
// //	}
// //    } else
// //#endif /* LIBXML_VALID_ENABLED */
// //           if (((ctxt->loadsubset & XML_SKIP_IDS) == 0) &&
// //               (ctxt->input->entity == NULL) &&
// //               /* Don't create IDs containing entity references */
// //               (ret->children != NULL) &&
// //               (ret->children->type == XML_TEXT_NODE) &&
// //               (ret->children->next == NULL)) {
// //        xmlChar *content = ret->children->content;
// //        /*
// //	 * when validating, the ID registration is done at the attribute
// //	 * validation level. Otherwise we have to do specific handling here.
// //	 */
// //        if ((prefix == ctxt->str_xml) &&
// //	           (localname[0] == 'i') && (localname[1] == 'd') &&
// //		   (localname[2] == 0)) {
// //	    /*
// //	     * Add the xml:id value
// //	     *
// //	     * Open issue: normalization of the value.
// //	     */
// //	    if (xmlValidateNCName(content, 1) != 0) {
// //	        xmlErrId(ctxt, XML_DTD_XMLID_VALUE,
// //                         "xml:id : attribute value %s is not an NCName\n",
// //                         content);
// //	    }
// //	    xmlAddID(&ctxt->vctxt, ctxt->myDoc, content, ret);
// //	} else {
// //            int res = xmlIsID(ctxt->myDoc, ctxt->node, ret);
// //
// //            if (res < 0)
// //                xmlCtxtErrMemory(ctxt);
// //            else if (res > 0)
// //                xmlAddID(&ctxt->vctxt, ctxt->myDoc, content, ret);
// //            else if (xmlIsRef(ctxt->myDoc, ctxt->node, ret))
// //                xmlAddRef(&ctxt->vctxt, ctxt->myDoc, content, ret);
// //	}
// //    }
// //    if (dup != NULL)
// //	xmlFree(dup);
// //
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
//     int xmlIsID(xmlDoc * doc, xmlNode * elem, xmlAttr * attr);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: int xmlIsID(xmlDoc * doc, xmlNode * elem, xmlAttr * attr);
// Fuzzer entrypoint: LLVMFuzzerTestOneInput
//
// This driver parses the incoming bytes as an XML document (with libxml2).
// It then picks the document root element and an attribute (creating one if needed),
// and calls xmlIsID(doc, elem, attr). Resources are cleaned up afterwards.
//
// Build note: link with libxml2 (e.g., `-lxml2`) and include libxml2 headers in include path.

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();
    LIBXML_TEST_VERSION

    /* Parse the input bytes as an XML document. xmlReadMemory accepts a char*
       buffer with an explicit length so embedded NULs are handled. */
    xmlDocPtr doc = NULL;
    int readSize = (Size > INT_MAX) ? INT_MAX : (int)Size;
    if (readSize > 0) {
        /* Use recover and nonet to reduce external interactions and allow parsing
           of potentially malformed inputs. */
        doc = xmlReadMemory((const char *)Data, readSize, "fuzz-input.xml", NULL,
                            XML_PARSE_RECOVER | XML_PARSE_NONET);
    }

    /* If parsing failed, create a minimal document so we still exercise xmlIsID. */
    if (doc == NULL) {
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc == NULL)
            return 0; /* memory issue, nothing to do */
        xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
        if (root == NULL) {
            xmlFreeDoc(doc);
            return 0;
        }
        xmlDocSetRootElement(doc, root);
        /* add an attribute named "id" so xmlIsID has something to inspect */
        xmlNewProp(root, BAD_CAST "id", BAD_CAST "fuzz");
    }

    /* Get the root element. If none, create one. */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        root = xmlNewNode(NULL, BAD_CAST "root");
        if (root != NULL)
            xmlDocSetRootElement(doc, root);
    }

    /* Select an attribute to test. Prefer an existing attribute; otherwise,
       create a simple 'id' attribute. */
    xmlAttrPtr attr = NULL;
    if (root != NULL) {
        attr = root->properties; /* first attribute on the node (may be NULL) */
        if (attr == NULL) {
            /* create an attribute so xmlIsID has a non-NULL attr to inspect */
            xmlNewProp(root, BAD_CAST "id", BAD_CAST "1");
            attr = root->properties;
        }
    }

    /* Call the target function. According to the API, return values:
       0 or 1 for false/true, or -1 on allocation failure. We ignore the result
       	6 the goal is to exercise behavior for various inputs. */
    (void)xmlIsID(doc, root, attr);

    /* Clean up */
    xmlFreeDoc(doc);

    /* Cleanup parser globals that may have been used.
       Note: xmlCleanupParser is safe but may have global effects if other
       threads are using libxml. For fuzzers running single-threaded it is OK. */
    xmlCleanupParser();

    return 0;
}
