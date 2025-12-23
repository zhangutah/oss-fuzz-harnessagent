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
// // const xmlChar *
// //xmlParseStartTag(xmlParserCtxt *ctxt) {
// //    const xmlChar *name;
// //    const xmlChar *attname;
// //    xmlChar *attvalue;
// //    const xmlChar **atts = ctxt->atts;
// //    int nbatts = 0;
// //    int maxatts = ctxt->maxatts;
// //    int i;
// //
// //    if (RAW != '<') return(NULL);
// //    NEXT1;
// //
// //    name = xmlParseName(ctxt);
// //    if (name == NULL) {
// //	xmlFatalErrMsg(ctxt, XML_ERR_NAME_REQUIRED,
// //	     "xmlParseStartTag: invalid element name\n");
// //        return(NULL);
// //    }
// //
// //    /*
// //     * Now parse the attributes, it ends up with the ending
// //     *
// //     * (S Attribute)* S?
// //     */
// //    SKIP_BLANKS;
// //    GROW;
// //
// //    while (((RAW != '>') &&
// //	   ((RAW != '/') || (NXT(1) != '>')) &&
// //	   (IS_BYTE_CHAR(RAW))) && (PARSER_STOPPED(ctxt) == 0)) {
// //	attname = xmlParseAttribute(ctxt, &attvalue);
// //        if (attname == NULL)
// //	    break;
// //        if (attvalue != NULL) {
// //	    /*
// //	     * [ WFC: Unique Att Spec ]
// //	     * No attribute name may appear more than once in the same
// //	     * start-tag or empty-element tag.
// //	     */
// //	    for (i = 0; i < nbatts;i += 2) {
// //	        if (xmlStrEqual(atts[i], attname)) {
// //		    xmlErrAttributeDup(ctxt, NULL, attname);
// //		    goto failed;
// //		}
// //	    }
// //	    /*
// //	     * Add the pair to atts
// //	     */
// //	    if (nbatts + 4 > maxatts) {
// //	        const xmlChar **n;
// //                int newSize;
// //
// //                newSize = xmlGrowCapacity(maxatts, sizeof(n[0]) * 2,
// //                                          11, XML_MAX_ATTRS);
// //                if (newSize < 0) {
// //		    xmlErrMemory(ctxt);
// //		    goto failed;
// //		}
// //#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// //                if (newSize < 2)
// //                    newSize = 2;
// //#endif
// //	        n = xmlRealloc(atts, newSize * sizeof(n[0]) * 2);
// //		if (n == NULL) {
// //		    xmlErrMemory(ctxt);
// //		    goto failed;
// //		}
// //		atts = n;
// //                maxatts = newSize * 2;
// //		ctxt->atts = atts;
// //		ctxt->maxatts = maxatts;
// //	    }
// //
// //	    atts[nbatts++] = attname;
// //	    atts[nbatts++] = attvalue;
// //	    atts[nbatts] = NULL;
// //	    atts[nbatts + 1] = NULL;
// //
// //            attvalue = NULL;
// //	}
// //
// //failed:
// //
// //        if (attvalue != NULL)
// //            xmlFree(attvalue);
// //
// //	GROW
// //	if ((RAW == '>') || (((RAW == '/') && (NXT(1) == '>'))))
// //	    break;
// //	if (SKIP_BLANKS == 0) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //			   "attributes construct error\n");
// //	}
// //	SHRINK;
// //        GROW;
// //    }
// //
// //    /*
// //     * SAX: Start of Element !
// //     */
// //    if ((ctxt->sax != NULL) && (ctxt->sax->startElement != NULL) &&
// //	(!ctxt->disableSAX)) {
// //	if (nbatts > 0)
// //	    ctxt->sax->startElement(ctxt->userData, name, atts);
// //	else
// //	    ctxt->sax->startElement(ctxt->userData, name, NULL);
// //    }
// //
// //    if (atts != NULL) {
// //        /* Free only the content strings */
// //        for (i = 1;i < nbatts;i+=2)
// //	    if (atts[i] != NULL)
// //	       xmlFree((xmlChar *) atts[i]);
// //    }
// //    return(name);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     const xmlChar * xmlParseAttribute(xmlParserCtxt * ctxt, xmlChar ** value);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>

/*
 * Fuzz driver for:
 *   const xmlChar * xmlParseAttribute(xmlParserCtxt * ctxt, xmlChar ** value);
 *
 * The fuzzer entry point used by libFuzzer:
 *   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 *
 * Strategy:
 * - Initialize libxml2 once (xmlInitParser).
 * - Create an in-memory parser context using the fuzzer input buffer.
 * - Call xmlParseAttribute on that context.
 * - Free any allocated resources (attribute value, parser context, documents).
 *
 * Notes:
 * - xmlParseAttribute may return a pointer into the parser context buffers;
 *   do NOT attempt to free that pointer directly.
 * - Only the returned attribute value (xmlChar *) should be freed with xmlFree().
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* initialize the library once */
        xmlInitParser();
        /* disable libxml2 generic error output to stderr to keep fuzz logs clean */
        xmlSetGenericErrorFunc(NULL, NULL);
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Make a null-terminated copy of the input for safety, xmlCreateMemoryParserCtxt
       accepts a buffer and a size, but some internals may expect a terminator. */
    char *buf = (char *)malloc(Size + 1);
    if (!buf)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Create a memory parser context from the input buffer */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt(buf, (int)Size);
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /* Ensure no leftover document pointers cause double-frees later */
    ctxt->myDoc = NULL;

    /* Call the function under test */
    xmlChar *value = NULL;
    /* xmlParseAttribute returns the attribute name (const xmlChar *), value is set via pointer */
    (void)xmlParseAttribute(ctxt, &value);

    /* Free the returned attribute value if allocated */
    if (value != NULL)
        xmlFree(value);

    /* If any document was produced, free it */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Free the parser context */
    xmlFreeParserCtxt(ctxt);

    free(buf);
    return 0;
}
