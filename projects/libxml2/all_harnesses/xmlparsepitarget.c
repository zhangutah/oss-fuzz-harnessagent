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
// // void
// //xmlParsePI(xmlParserCtxt *ctxt) {
// //    xmlChar *buf = NULL;
// //    size_t len = 0;
// //    size_t size = XML_PARSER_BUFFER_SIZE;
// //    size_t maxLength = (ctxt->options & XML_PARSE_HUGE) ?
// //                       XML_MAX_HUGE_LENGTH :
// //                       XML_MAX_TEXT_LENGTH;
// //    int cur, l;
// //    const xmlChar *target;
// //
// //    if ((RAW == '<') && (NXT(1) == '?')) {
// //	/*
// //	 * this is a Processing Instruction.
// //	 */
// //	SKIP(2);
// //
// //	/*
// //	 * Parse the target name and check for special support like
// //	 * namespace.
// //	 */
// //        target = xmlParsePITarget(ctxt);
// //	if (target != NULL) {
// //	    if ((RAW == '?') && (NXT(1) == '>')) {
// //		SKIP(2);
// //
// //		/*
// //		 * SAX: PI detected.
// //		 */
// //		if ((ctxt->sax) && (!ctxt->disableSAX) &&
// //		    (ctxt->sax->processingInstruction != NULL))
// //		    ctxt->sax->processingInstruction(ctxt->userData,
// //		                                     target, NULL);
// //		return;
// //	    }
// //	    buf = xmlMalloc(size);
// //	    if (buf == NULL) {
// //		xmlErrMemory(ctxt);
// //		return;
// //	    }
// //	    if (SKIP_BLANKS == 0) {
// //		xmlFatalErrMsgStr(ctxt, XML_ERR_SPACE_REQUIRED,
// //			  "ParsePI: PI %s space expected\n", target);
// //	    }
// //	    cur = xmlCurrentCharRecover(ctxt, &l);
// //	    while (IS_CHAR(cur) && /* checked */
// //		   ((cur != '?') || (NXT(1) != '>'))) {
// //		if (len + 5 >= size) {
// //		    xmlChar *tmp;
// //                    int newSize;
// //
// //                    newSize = xmlGrowCapacity(size, 1, 1, maxLength);
// //                    if (newSize < 0) {
// //                        xmlFatalErrMsgStr(ctxt, XML_ERR_PI_NOT_FINISHED,
// //                                          "PI %s too big found", target);
// //                        xmlFree(buf);
// //                        return;
// //                    }
// //		    tmp = xmlRealloc(buf, newSize);
// //		    if (tmp == NULL) {
// //			xmlErrMemory(ctxt);
// //			xmlFree(buf);
// //			return;
// //		    }
// //		    buf = tmp;
// //                    size = newSize;
// //		}
// //		COPY_BUF(buf, len, cur);
// //		NEXTL(l);
// //		cur = xmlCurrentCharRecover(ctxt, &l);
// //	    }
// //	    buf[len] = 0;
// //	    if (cur != '?') {
// //		xmlFatalErrMsgStr(ctxt, XML_ERR_PI_NOT_FINISHED,
// //		      "ParsePI: PI %s never end ...\n", target);
// //	    } else {
// //		SKIP(2);
// //
// //#ifdef LIBXML_CATALOG_ENABLED
// //		if ((ctxt->inSubset == 0) &&
// //		    (xmlStrEqual(target, XML_CATALOG_PI))) {
// //		    xmlCatalogAllow allow = xmlCatalogGetDefaults();
// //
// //		    if ((ctxt->options & XML_PARSE_CATALOG_PI) &&
// //                        ((allow == XML_CATA_ALLOW_DOCUMENT) ||
// //			 (allow == XML_CATA_ALLOW_ALL)))
// //			xmlParseCatalogPI(ctxt, buf);
// //		}
// //#endif
// //
// //		/*
// //		 * SAX: PI detected.
// //		 */
// //		if ((ctxt->sax) && (!ctxt->disableSAX) &&
// //		    (ctxt->sax->processingInstruction != NULL))
// //		    ctxt->sax->processingInstruction(ctxt->userData,
// //		                                     target, buf);
// //	    }
// //	    xmlFree(buf);
// //	} else {
// //	    xmlFatalErr(ctxt, XML_ERR_PI_NOT_STARTED, NULL);
// //	}
// //    }
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     const xmlChar * xmlParsePITarget(xmlParserCtxt * ctxt);
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
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>

/*
 Fuzz driver for:
   const xmlChar * xmlParsePITarget(xmlParserCtxt * ctxt);

 Entry point for libFuzzer:
   int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* xmlCreateMemoryParserCtxt takes an int size, guard against huge sizes */
    if (Size > INT_MAX) return 0;

    /* Copy input to a NUL-terminated buffer because some parser helpers expect strings */
    char *buffer = (char *)malloc(Size + 1);
    if (buffer == NULL) return 0;
    memcpy(buffer, Data, Size);
    buffer[Size] = '\0';

    /* Ensure the libxml2 library is initialized (safe to call repeatedly) */
    xmlInitParser();

    /* Create a memory parser context from the fuzz input */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt(buffer, (int)Size);
    if (ctxt == NULL) {
        free(buffer);
        return 0;
    }

    /*
     Call the target function. It returns a pointer into parser internals (xmlChar*).
     We don't dereference it further to avoid depending on parser-owned memory lifetime.
    */
    (void)xmlParsePITarget(ctxt);

    /* Clean up parser context and buffer */
    xmlFreeParserCtxt(ctxt);
    free(buffer);

    return 0;
}