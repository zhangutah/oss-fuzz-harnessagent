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
// //xmlParseTextDecl(xmlParserCtxt *ctxt) {
// //    xmlChar *version;
// //
// //    /*
// //     * We know that '<?xml' is here.
// //     */
// //    if ((CMP5(CUR_PTR, '<', '?', 'x', 'm', 'l')) && (IS_BLANK_CH(NXT(5)))) {
// //	SKIP(5);
// //    } else {
// //	xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_STARTED, NULL);
// //	return;
// //    }
// //
// //    if (SKIP_BLANKS == 0) {
// //	xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //		       "Space needed after '<?xml'\n");
// //    }
// //
// //    /*
// //     * We may have the VersionInfo here.
// //     */
// //    version = xmlParseVersionInfo(ctxt);
// //    if (version == NULL) {
// //	version = xmlCharStrdup(XML_DEFAULT_VERSION);
// //        if (version == NULL) {
// //            xmlErrMemory(ctxt);
// //            return;
// //        }
// //    } else {
// //	if (SKIP_BLANKS == 0) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //		           "Space needed here\n");
// //	}
// //    }
// //    ctxt->input->version = version;
// //
// //    /*
// //     * We must have the encoding declaration
// //     */
// //    xmlParseEncodingDecl(ctxt);
// //
// //    SKIP_BLANKS;
// //    if ((RAW == '?') && (NXT(1) == '>')) {
// //        SKIP(2);
// //    } else if (RAW == '>') {
// //        /* Deprecated old WD ... */
// //	xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, NULL);
// //	NEXT;
// //    } else {
// //        int c;
// //
// //	xmlFatalErr(ctxt, XML_ERR_XMLDECL_NOT_FINISHED, NULL);
// //        while ((PARSER_STOPPED(ctxt) == 0) && ((c = CUR) != 0)) {
// //            NEXT;
// //            if (c == '>')
// //                break;
// //        }
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
//     const xmlChar * xmlParseEncodingDecl(xmlParserCtxt * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlerror.h>

/*
 * Fuzzer entry point for fuzzing:
 *     const xmlChar * xmlParseEncodingDecl(xmlParserCtxt * ctxt);
 *
 * Strategy:
 * - Create a push parser context initialized with the fuzzer input bytes.
 * - Call xmlParseEncodingDecl() on that context.
 * - Clean up.
 *
 * Notes:
 * - xmlCreatePushParserCtxt accepts an initial chunk and size; the parser's
 *   internal input buffer will reference that data so the function under test
 *   can operate on it.
 * - We disable libxml2 generic error reporting to avoid noisy stderr output
 *   during fuzzing.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Nothing to do for empty input */
    if (Data == NULL || Size == 0) return 0;

    /* Initialize the library (no-op if already initialized) */
    xmlInitParser();

    /* Silence libxml2 error output to stderr to avoid cluttering fuzzer logs */
    xmlSetGenericErrorFunc(NULL, NULL);

    /* xmlCreatePushParserCtxt takes an int size; clamp to INT_MAX if needed */
    int chunkSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a push parser context with the provided data chunk */
    xmlParserCtxtPtr ctxt = xmlCreatePushParserCtxt(NULL, NULL, (const char *)Data, chunkSize, NULL);
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Call the function under test. Result is ignored; we just want to exercise code paths. */
    (void)xmlParseEncodingDecl(ctxt);

    /* Free the parser context and cleanup */
    xmlFreeParserCtxt(ctxt);
    xmlCleanupParser();

    return 0;
}
