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
// //xmlTextReaderValidatePush(xmlTextReaderPtr reader) {
// //    xmlNodePtr node = reader->node;
// //
// //#ifdef LIBXML_VALID_ENABLED
// //    if ((reader->validate == XML_TEXTREADER_VALIDATE_DTD) &&
// //        (reader->ctxt != NULL) && (reader->ctxt->validate == 1)) {
// //	if ((node->ns == NULL) || (node->ns->prefix == NULL)) {
// //	    reader->ctxt->valid &= xmlValidatePushElement(&reader->ctxt->vctxt,
// //				    reader->ctxt->myDoc, node, node->name);
// //	} else {
// //            xmlChar buf[50];
// //	    xmlChar *qname;
// //
// //	    qname = xmlBuildQName(node->name, node->ns->prefix, buf, 50);
// //            if (qname == NULL) {
// //                xmlTextReaderErrMemory(reader);
// //                return(-1);
// //            }
// //	    reader->ctxt->valid &= xmlValidatePushElement(&reader->ctxt->vctxt,
// //				    reader->ctxt->myDoc, node, qname);
// //            if (qname != buf)
// //	        xmlFree(qname);
// //	}
// //        /*if (reader->ctxt->errNo == XML_ERR_NO_MEMORY) {
// //            reader->mode = XML_TEXTREADER_MODE_ERROR;
// //            reader->state = XML_TEXTREADER_ERROR;
// //            return(-1);
// //        }*/
// //    }
// //#endif /* LIBXML_VALID_ENABLED */
// //#ifdef LIBXML_RELAXNG_ENABLED
// //    if ((reader->validate == XML_TEXTREADER_VALIDATE_RNG) &&
// //               (reader->rngValidCtxt != NULL)) {
// //	int ret;
// //
// //	if (reader->rngFullNode != NULL) return(0);
// //	ret = xmlRelaxNGValidatePushElement(reader->rngValidCtxt,
// //	                                    reader->ctxt->myDoc,
// //					    node);
// //	if (ret == 0) {
// //	    /*
// //	     * this element requires a full tree
// //	     */
// //	    node = xmlTextReaderExpand(reader);
// //	    if (node == NULL) {
// //	        ret = -1;
// //	    } else {
// //		ret = xmlRelaxNGValidateFullElement(reader->rngValidCtxt,
// //						    reader->ctxt->myDoc,
// //						    node);
// //		reader->rngFullNode = node;
// //	    }
// //	}
// //	if (ret != 1)
// //	    reader->rngValidErrors++;
// //    }
// //#endif
// //
// //    return(0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlValidatePushElement(xmlValidCtxt * ctxt, xmlDoc * doc, xmlNode * elem, const xmlChar * qname);
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

#include <libxml/valid.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlstring.h>

/*
 Fuzz driver for:
   int xmlValidatePushElement(xmlValidCtxt * ctxt, xmlDoc * doc,
                              xmlNode * elem, const xmlChar * qname);
 Entry point: LLVMFuzzerTestOneInput
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Initialize the libxml2 parser (safe to call multiple times) */
    xmlInitParser();

    /* Create a validation context */
    xmlValidCtxt *vctxt = xmlNewValidCtxt();
    if (vctxt == NULL)
        return 0;

    /* Create a minimal document */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        xmlFreeValidCtxt(vctxt);
        return 0;
    }

    /* Derive a node name from input data (limit length to avoid huge allocations) */
    const int MAX_NAME = 128;
    int name_len = 0;
    if (Size > 0) {
        name_len = (Size > (size_t)MAX_NAME) ? MAX_NAME : (int)Size;
    }

    xmlChar *node_name = NULL;
    xmlNodePtr elem = NULL;

    if (name_len > 0) {
        /* Use the prefix of Data as the node name (may contain arbitrary bytes) */
        node_name = xmlStrndup((const xmlChar *)Data, name_len);
        /* Create a node attached to the document (xmlNewDocNode associates the node->doc) */
        elem = xmlNewDocNode(doc, NULL, node_name, NULL);
        /* xmlNewDocNode duplicates the name for the node; free our temporary one */
        xmlFree(node_name);
        node_name = NULL;
    } else {
        /* Fallback name when there's no data */
        elem = xmlNewDocNode(doc, NULL, BAD_CAST "fuzznode", NULL);
    }

    if (elem == NULL) {
        xmlFreeDoc(doc);
        xmlFreeValidCtxt(vctxt);
        return 0;
    }

    /*
      Ensure the node is part of the document so freeing the doc will free the node.
      xmlNewDocNode should set node->doc to doc, but set as root to be safe.
    */
    xmlDocSetRootElement(doc, elem);

    /* Prepare qname from a slice of Data (possibly NULL) */
    const xmlChar *qname = NULL;
    xmlChar *qname_dup = NULL;
    if (Size > 0) {
        /* Choose an offset to increase coverage: use up to half the input as qname */
        size_t offset = (Size > 1) ? (Size / 3) : 0;
        size_t qlen = Size - offset;
        if (qlen > (size_t)MAX_NAME) qlen = MAX_NAME;
        if (qlen > 0) {
            qname_dup = xmlStrndup((const xmlChar *)(Data + offset), (int)qlen);
            qname = qname_dup;
        }
    }

    /* Optionally set the doc pointer in the validation context to the document */
    vctxt->doc = doc;

    /* Call the target function under test */
    /* This may return 0/1 or other values depending on validation; we ignore it. */
    (void)xmlValidatePushElement(vctxt, doc, elem, qname);

    /* Clean up */
    if (qname_dup != NULL)
        xmlFree(qname_dup);

    /* Free the document (frees elem if attached) */
    xmlFreeDoc(doc);

    /* Free the validation context */
    xmlFreeValidCtxt(vctxt);

    /* Cleanup global parser state (no-op for many builds but safe) */
    xmlCleanupParser();

    return 0;
}
