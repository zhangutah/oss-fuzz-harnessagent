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
// //xmlParseContentInternal(xmlParserCtxtPtr ctxt) {
// //    int oldNameNr = ctxt->nameNr;
// //    int oldSpaceNr = ctxt->spaceNr;
// //    int oldNodeNr = ctxt->nodeNr;
// //
// //    GROW;
// //    while ((ctxt->input->cur < ctxt->input->end) &&
// //	   (PARSER_STOPPED(ctxt) == 0)) {
// //	const xmlChar *cur = ctxt->input->cur;
// //
// //	/*
// //	 * First case : a Processing Instruction.
// //	 */
// //	if ((*cur == '<') && (cur[1] == '?')) {
// //	    xmlParsePI(ctxt);
// //	}
// //
// //	/*
// //	 * Second case : a CDSection
// //	 */
// //	/* 2.6.0 test was *cur not RAW */
// //	else if (CMP9(CUR_PTR, '<', '!', '[', 'C', 'D', 'A', 'T', 'A', '[')) {
// //	    xmlParseCDSect(ctxt);
// //	}
// //
// //	/*
// //	 * Third case :  a comment
// //	 */
// //	else if ((*cur == '<') && (NXT(1) == '!') &&
// //		 (NXT(2) == '-') && (NXT(3) == '-')) {
// //	    xmlParseComment(ctxt);
// //	}
// //
// //	/*
// //	 * Fourth case :  a sub-element.
// //	 */
// //	else if (*cur == '<') {
// //            if (NXT(1) == '/') {
// //                if (ctxt->nameNr <= oldNameNr)
// //                    break;
// //	        xmlParseElementEnd(ctxt);
// //            } else {
// //	        xmlParseElementStart(ctxt);
// //            }
// //	}
// //
// //	/*
// //	 * Fifth case : a reference. If if has not been resolved,
// //	 *    parsing returns it's Name, create the node
// //	 */
// //
// //	else if (*cur == '&') {
// //	    xmlParseReference(ctxt);
// //	}
// //
// //	/*
// //	 * Last case, text. Note that References are handled directly.
// //	 */
// //	else {
// //	    xmlParseCharDataInternal(ctxt, 0);
// //	}
// //
// //	SHRINK;
// //	GROW;
// //    }
// //
// //    if ((ctxt->nameNr > oldNameNr) &&
// //        (ctxt->input->cur >= ctxt->input->end) &&
// //        (ctxt->wellFormed)) {
// //        const xmlChar *name = ctxt->nameTab[ctxt->nameNr - 1];
// //        int line = ctxt->pushTab[ctxt->nameNr - 1].line;
// //        xmlFatalErrMsgStrIntStr(ctxt, XML_ERR_TAG_NOT_FINISHED,
// //                "Premature end of data in tag %s line %d\n",
// //                name, line, NULL);
// //    }
// //
// //    /*
// //     * Clean up in error case
// //     */
// //
// //    while (ctxt->nodeNr > oldNodeNr)
// //        nodePop(ctxt);
// //
// //    while (ctxt->nameNr > oldNameNr) {
// //        xmlStartTag *tag = &ctxt->pushTab[ctxt->nameNr - 1];
// //
// //        if (tag->nsNr != 0)
// //            xmlParserNsPop(ctxt, tag->nsNr);
// //
// //        namePop(ctxt);
// //    }
// //
// //    while (ctxt->spaceNr > oldSpaceNr)
// //        spacePop(ctxt);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     void xmlParseReference(xmlParserCtxt * ctxt);
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

/* Use absolute project header path as available in the workspace */
#include "/src/libxml2/include/libxml/parserInternals.h"

/*
 * Fuzzer entry point.
 *
 * This harness creates a push parser context with the input being the fuzzer
 * data prefixed by an '&' character to exercise xmlParseReference's handling
 * of entity and character references. It calls xmlParseReference() and then
 * cleans up.
 */

/* Initialize libxml once at load time, and cleanup at unload time. */
__attribute__((constructor))
static void fuzz_init(void) {
    xmlInitParser();
}

__attribute__((destructor))
static void fuzz_fini(void) {
    xmlCleanupParser();
}

/* libFuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Ensure we can cast size to int safely for xmlCreatePushParserCtxt. */
    int maxAllowed = INT_MAX - 2;
    int inSize = (Size > (size_t)maxAllowed) ? maxAllowed : (int)Size;

    /* Allocate a buffer with a leading '&' to trigger reference parsing. */
    int bufSize = inSize + 1; /* +1 for the leading '&' */
    char *buf = (char *)malloc((size_t)bufSize);
    if (buf == NULL)
        return 0;

    buf[0] = '&';
    memcpy(buf + 1, Data, (size_t)inSize);

    /* Create a push parser context with the buffer. */
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, buf, bufSize, "fuzz");
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /*
     * The parser created by xmlCreatePushParserCtxt will own references to the
     * input buffer internally. We still free our local copy after the call to
     * xmlFreeParserCtxt below (the parser makes its own copy or manages it).
     *
     * Call the target function under test.
     */
    xmlParseReference(ctxt);

    /* Clean up parser context */
    xmlFreeParserCtxt(ctxt);

    /* Free our allocated buffer */
    free(buf);

    return 0;
}
