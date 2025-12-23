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
// //xmlParseElementStart(xmlParserCtxtPtr ctxt) {
// //    int maxDepth = (ctxt->options & XML_PARSE_HUGE) ? 2048 : 256;
// //    const xmlChar *name;
// //    const xmlChar *prefix = NULL;
// //    const xmlChar *URI = NULL;
// //    xmlParserNodeInfo node_info;
// //    int line;
// //    xmlNodePtr cur;
// //    int nbNs = 0;
// //
// //    if (ctxt->nameNr > maxDepth) {
// //        xmlFatalErrMsgInt(ctxt, XML_ERR_RESOURCE_LIMIT,
// //                "Excessive depth in document: %d use XML_PARSE_HUGE option\n",
// //                ctxt->nameNr);
// //	return(-1);
// //    }
// //
// //    /* Capture start position */
// //    if (ctxt->record_info) {
// //        node_info.begin_pos = ctxt->input->consumed +
// //                          (CUR_PTR - ctxt->input->base);
// //	node_info.begin_line = ctxt->input->line;
// //    }
// //
// //    if (ctxt->spaceNr == 0)
// //	spacePush(ctxt, -1);
// //    else if (*ctxt->space == -2)
// //	spacePush(ctxt, -1);
// //    else
// //	spacePush(ctxt, *ctxt->space);
// //
// //    line = ctxt->input->line;
// //#ifdef LIBXML_SAX1_ENABLED
// //    if (ctxt->sax2)
// //#endif /* LIBXML_SAX1_ENABLED */
// //        name = xmlParseStartTag2(ctxt, &prefix, &URI, &nbNs);
// //#ifdef LIBXML_SAX1_ENABLED
// //    else
// //	name = xmlParseStartTag(ctxt);
// //#endif /* LIBXML_SAX1_ENABLED */
// //    if (name == NULL) {
// //	spacePop(ctxt);
// //        return(-1);
// //    }
// //    nameNsPush(ctxt, name, prefix, URI, line, nbNs);
// //    cur = ctxt->node;
// //
// //#ifdef LIBXML_VALID_ENABLED
// //    /*
// //     * [ VC: Root Element Type ]
// //     * The Name in the document type declaration must match the element
// //     * type of the root element.
// //     */
// //    if (ctxt->validate && ctxt->wellFormed && ctxt->myDoc &&
// //        ctxt->node && (ctxt->node == ctxt->myDoc->children))
// //        ctxt->valid &= xmlValidateRoot(&ctxt->vctxt, ctxt->myDoc);
// //#endif /* LIBXML_VALID_ENABLED */
// //
// //    /*
// //     * Check for an Empty Element.
// //     */
// //    if ((RAW == '/') && (NXT(1) == '>')) {
// //        SKIP(2);
// //	if (ctxt->sax2) {
// //	    if ((ctxt->sax != NULL) && (ctxt->sax->endElementNs != NULL) &&
// //		(!ctxt->disableSAX))
// //		ctxt->sax->endElementNs(ctxt->userData, name, prefix, URI);
// //#ifdef LIBXML_SAX1_ENABLED
// //	} else {
// //	    if ((ctxt->sax != NULL) && (ctxt->sax->endElement != NULL) &&
// //		(!ctxt->disableSAX))
// //		ctxt->sax->endElement(ctxt->userData, name);
// //#endif /* LIBXML_SAX1_ENABLED */
// //	}
// //	namePop(ctxt);
// //	spacePop(ctxt);
// //	if (nbNs > 0)
// //	    xmlParserNsPop(ctxt, nbNs);
// //	if (cur != NULL && ctxt->record_info) {
// //            node_info.node = cur;
// //            node_info.end_pos = ctxt->input->consumed +
// //                                (CUR_PTR - ctxt->input->base);
// //            node_info.end_line = ctxt->input->line;
// //            xmlParserAddNodeInfo(ctxt, &node_info);
// //	}
// //	return(1);
// //    }
// //    if (RAW == '>') {
// //        NEXT1;
// //        if (cur != NULL && ctxt->record_info) {
// //            node_info.node = cur;
// //            node_info.end_pos = 0;
// //            node_info.end_line = 0;
// //            xmlParserAddNodeInfo(ctxt, &node_info);
// //        }
// //    } else {
// //        xmlFatalErrMsgStrIntStr(ctxt, XML_ERR_GT_REQUIRED,
// //		     "Couldn't find end of Start Tag %s line %d\n",
// //		                name, line, NULL);
// //
// //	/*
// //	 * end of parsing of this node.
// //	 */
// //	nodePop(ctxt);
// //	namePop(ctxt);
// //	spacePop(ctxt);
// //	if (nbNs > 0)
// //	    xmlParserNsPop(ctxt, nbNs);
// //	return(-1);
// //    }
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
//     const xmlChar * xmlParseStartTag(xmlParserCtxt * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: const xmlChar * xmlParseStartTag(xmlParserCtxt * ctxt);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver creates a memory-backed xmlParserCtxt from the fuzzer input
// and invokes xmlParseStartTag on it, then frees the context.
//
// Note: headers use project includes discovered in the repository. Depending
// on your build environment you may prefer <libxml/parser.h> and
// <libxml/parserInternals.h> instead of the absolute paths below.

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>

#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"

/* Ensure the libxml parser is initialized once per process. */
static void ensure_libxml_inited(void) {
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        inited = 1;
    }
}

/* Fuzzer entry point required by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* No work for empty input. */
    if (Data == NULL || Size == 0) return 0;

    ensure_libxml_inited();

    /* xmlCreateMemoryParserCtxt takes an int size; clamp to INT_MAX. */
    if (Size > (size_t)INT_MAX) Size = (size_t)INT_MAX;

    /* Create a parser context backed by the fuzzer data buffer. */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt((const char *)Data, (int)Size);
    if (ctxt == NULL) {
        return 0;
    }

    /*
     * Call the target function. xmlParseStartTag expects the current input
     * to point at a '<' for a valid start tag, but we feed arbitrary data
     * to exercise parsing logic and potential edge-cases.
     */
    (void)xmlParseStartTag(ctxt);

    /* Free parser context and associated resources. */
    xmlFreeParserCtxt(ctxt);

    /* Do not call xmlCleanupParser() here  it would free global state and
     * is generally called once at program exit. */
    return 0;
}