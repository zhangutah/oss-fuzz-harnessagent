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
// //xmlValidateOneAttribute(xmlValidCtxt *ctxt, xmlDoc *doc,
// //                        xmlNode *elem, xmlAttr *attr, const xmlChar *value)
// //{
// //    xmlAttributePtr attrDecl =  NULL;
// //    const xmlChar *aprefix;
// //    int val;
// //    int ret = 1;
// //
// //    CHECK_DTD;
// //    if ((elem == NULL) || (elem->name == NULL)) return(0);
// //    if ((attr == NULL) || (attr->name == NULL)) return(0);
// //
// //    aprefix = (attr->ns != NULL) ? attr->ns->prefix : NULL;
// //
// //    if ((elem->ns != NULL) && (elem->ns->prefix != NULL)) {
// //	xmlChar fn[50];
// //	xmlChar *fullname;
// //
// //	fullname = xmlBuildQName(elem->name, elem->ns->prefix, fn, 50);
// //	if (fullname == NULL) {
// //            xmlVErrMemory(ctxt);
// //	    return(0);
// //        }
// //        attrDecl = xmlGetDtdQAttrDesc(doc->intSubset, fullname,
// //                                      attr->name, aprefix);
// //        if ((attrDecl == NULL) && (doc->extSubset != NULL))
// //            attrDecl = xmlGetDtdQAttrDesc(doc->extSubset, fullname,
// //                                          attr->name, aprefix);
// //	if ((fullname != fn) && (fullname != elem->name))
// //	    xmlFree(fullname);
// //    }
// //    if (attrDecl == NULL) {
// //        attrDecl = xmlGetDtdQAttrDesc(doc->intSubset, elem->name,
// //                                      attr->name, aprefix);
// //        if ((attrDecl == NULL) && (doc->extSubset != NULL))
// //            attrDecl = xmlGetDtdQAttrDesc(doc->extSubset, elem->name,
// //                                          attr->name, aprefix);
// //    }
// //
// //
// //    /* Validity Constraint: Attribute Value Type */
// //    if (attrDecl == NULL) {
// //	xmlErrValidNode(ctxt, elem, XML_DTD_UNKNOWN_ATTRIBUTE,
// //	       "No declaration for attribute %s of element %s\n",
// //	       attr->name, elem->name, NULL);
// //	return(0);
// //    }
// //    if (attr->id != NULL)
// //        xmlRemoveID(doc, attr);
// //    attr->atype = attrDecl->atype;
// //
// //    val = xmlValidateAttributeValueInternal(doc, attrDecl->atype, value);
// //    if (val == 0) {
// //	    xmlErrValidNode(ctxt, elem, XML_DTD_ATTRIBUTE_VALUE,
// //	   "Syntax of value for attribute %s of %s is not valid\n",
// //	       attr->name, elem->name, NULL);
// //        ret = 0;
// //    }
// //
// //    /* Validity constraint: Fixed Attribute Default */
// //    if (attrDecl->def == XML_ATTRIBUTE_FIXED) {
// //	if (!xmlStrEqual(value, attrDecl->defaultValue)) {
// //	    xmlErrValidNode(ctxt, elem, XML_DTD_ATTRIBUTE_DEFAULT,
// //	   "Value for attribute %s of %s is different from default \"%s\"\n",
// //		   attr->name, elem->name, attrDecl->defaultValue);
// //	    ret = 0;
// //	}
// //    }
// //
// //    /* Validity Constraint: ID uniqueness */
// //    if (attrDecl->atype == XML_ATTRIBUTE_ID &&
// //        (ctxt == NULL || (ctxt->flags & XML_VCTXT_IN_ENTITY) == 0)) {
// //        if (xmlAddID(ctxt, doc, value, attr) == NULL)
// //	    ret = 0;
// //    }
// //
// //    if ((attrDecl->atype == XML_ATTRIBUTE_IDREF) ||
// //	(attrDecl->atype == XML_ATTRIBUTE_IDREFS)) {
// //        if (xmlAddRef(ctxt, doc, value, attr) == NULL)
// //	    ret = 0;
// //    }
// //
// //    /* Validity Constraint: Notation Attributes */
// //    if (attrDecl->atype == XML_ATTRIBUTE_NOTATION) {
// //        xmlEnumerationPtr tree = attrDecl->tree;
// //        xmlNotationPtr nota;
// //
// //        /* First check that the given NOTATION was declared */
// //	nota = xmlGetDtdNotationDesc(doc->intSubset, value);
// //	if (nota == NULL)
// //	    nota = xmlGetDtdNotationDesc(doc->extSubset, value);
// //
// //	if (nota == NULL) {
// //	    xmlErrValidNode(ctxt, elem, XML_DTD_UNKNOWN_NOTATION,
// //       "Value \"%s\" for attribute %s of %s is not a declared Notation\n",
// //		   value, attr->name, elem->name);
// //	    ret = 0;
// //        }
// //
// //	/* Second, verify that it's among the list */
// //	while (tree != NULL) {
// //	    if (xmlStrEqual(tree->name, value)) break;
// //	    tree = tree->next;
// //	}
// //	if (tree == NULL) {
// //	    xmlErrValidNode(ctxt, elem, XML_DTD_NOTATION_VALUE,
// //"Value \"%s\" for attribute %s of %s is not among the enumerated notations\n",
// //		   value, attr->name, elem->name);
// //	    ret = 0;
// //	}
// //    }
// //
// //    /* Validity Constraint: Enumeration */
// //    if (attrDecl->atype == XML_ATTRIBUTE_ENUMERATION) {
// //        xmlEnumerationPtr tree = attrDecl->tree;
// //	while (tree != NULL) {
// //	    if (xmlStrEqual(tree->name, value)) break;
// //	    tree = tree->next;
// //	}
// //	if (tree == NULL) {
// //	    xmlErrValidNode(ctxt, elem, XML_DTD_ATTRIBUTE_VALUE,
// //       "Value \"%s\" for attribute %s of %s is not among the enumerated set\n",
// //		   value, attr->name, elem->name);
// //	    ret = 0;
// //	}
// //    }
// //
// //    /* Fixed Attribute Default */
// //    if ((attrDecl->def == XML_ATTRIBUTE_FIXED) &&
// //        (!xmlStrEqual(attrDecl->defaultValue, value))) {
// //	xmlErrValidNode(ctxt, elem, XML_DTD_ATTRIBUTE_VALUE,
// //	   "Value for attribute %s of %s must be \"%s\"\n",
// //	       attr->name, elem->name, attrDecl->defaultValue);
// //        ret = 0;
// //    }
// //
// //    /* Extra check for the attribute value */
// //    ret &= xmlValidateAttributeValue2(ctxt, doc, attr->name,
// //				      attrDecl->atype, value);
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
//     xmlRef * xmlAddRef(xmlValidCtxt * ctxt, xmlDoc * doc, const xmlChar * value, xmlAttr * attr);
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
#include <stdio.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/valid.h>

/*
 Fuzzer entry point
 extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser environment */
    xmlInitParser();

    /* Copy input into a NUL-terminated buffer so we can create C strings */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Split the buffer into two parts: name and value.
       If Size == 1, the name may be empty and the value be the single byte. */
    size_t split = Size / 2;
    const xmlChar *name = (const xmlChar *)(buf);
    const xmlChar *value = (const xmlChar *)(buf + split);

    /* Create a minimal document and a root node */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        free(buf);
        xmlCleanupParser();
        return 0;
    }

    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    if (root == NULL) {
        xmlFreeDoc(doc);
        free(buf);
        xmlCleanupParser();
        return 0;
    }
    xmlDocSetRootElement(doc, root);

    /* Create an attribute on the root node using fuzzed name/value */
    /* xmlNewProp returns an xmlAttrPtr attached to the node */
    xmlAttrPtr attr = xmlNewProp(root, name, value);

    /* Create or initialize a validation context.
       Use xmlNewValidCtxt if available; otherwise fall back to a zeroed struct. */
#ifdef LIBXML_VALID_ENABLED
    xmlValidCtxtPtr vctxt = xmlNewValidCtxt();
    if (vctxt == NULL) {
        /* fallback to a calloc'd struct if allocation fails */
        vctxt = (xmlValidCtxtPtr)calloc(1, sizeof(xmlValidCtxt));
    }
#else
    xmlValidCtxtPtr vctxt = (xmlValidCtxtPtr)calloc(1, sizeof(xmlValidCtxt));
#endif

    /* Call the target function with the fuzzed inputs.
       xmlAddRef returns an xmlRef* which may be NULL on error. We do not dereference it. */
    (void)xmlAddRef(vctxt, doc, value, attr);

    /* Also exercise some edge cases to trigger early returns in xmlAddRef:
       - NULL doc
       - NULL value
       - NULL attr
       (These are harmless calls and can improve coverage.) */
    (void)xmlAddRef(vctxt, NULL, value, attr);
    (void)xmlAddRef(vctxt, doc, NULL, attr);
    (void)xmlAddRef(vctxt, doc, value, NULL);

    /* Cleanup: free validation context if we allocated it manually or via xmlNewValidCtxt */
#ifdef LIBXML_VALID_ENABLED
    /* If vctxt was returned by xmlNewValidCtxt, free it using xmlFreeValidCtxt.
       There's no reliable way to know which branch allocated it above, but
       calling xmlFreeValidCtxt on a pointer returned by xmlNewValidCtxt is correct.
       If we fell back to calloc earlier and xmlFreeValidCtxt is available, it should still free safely.
       To be conservative, if xmlFreeValidCtxt is available call it, otherwise free. */
    xmlFreeValidCtxt(vctxt);
#else
    free(vctxt);
#endif

    /* Free the document (this also frees the nodes and attributes attached) */
    xmlFreeDoc(doc);

    /* Free the copied buffer */
    free(buf);

    /* Cleanup libxml2 global state */
    xmlCleanupParser();

    return 0;
}
