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
// //xmlParseDocTypeDecl(xmlParserCtxt *ctxt) {
// //    const xmlChar *name = NULL;
// //    xmlChar *publicId = NULL;
// //    xmlChar *URI = NULL;
// //
// //    /*
// //     * We know that '<!DOCTYPE' has been detected.
// //     */
// //    SKIP(9);
// //
// //    if (SKIP_BLANKS == 0) {
// //        xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //                       "Space required after 'DOCTYPE'\n");
// //    }
// //
// //    /*
// //     * Parse the DOCTYPE name.
// //     */
// //    name = xmlParseName(ctxt);
// //    if (name == NULL) {
// //	xmlFatalErrMsg(ctxt, XML_ERR_NAME_REQUIRED,
// //		       "xmlParseDocTypeDecl : no DOCTYPE name !\n");
// //    }
// //    ctxt->intSubName = name;
// //
// //    SKIP_BLANKS;
// //
// //    /*
// //     * Check for public and system identifier (URI)
// //     */
// //    URI = xmlParseExternalID(ctxt, &publicId, 1);
// //
// //    if ((URI != NULL) || (publicId != NULL)) {
// //        ctxt->hasExternalSubset = 1;
// //    }
// //    ctxt->extSubURI = URI;
// //    ctxt->extSubSystem = publicId;
// //
// //    SKIP_BLANKS;
// //
// //    /*
// //     * Create and update the internal subset.
// //     */
// //    if ((ctxt->sax != NULL) && (ctxt->sax->internalSubset != NULL) &&
// //	(!ctxt->disableSAX))
// //	ctxt->sax->internalSubset(ctxt->userData, name, publicId, URI);
// //
// //    if ((RAW != '[') && (RAW != '>')) {
// //	xmlFatalErr(ctxt, XML_ERR_DOCTYPE_NOT_FINISHED, NULL);
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
//     xmlChar * xmlParseExternalID(xmlParserCtxt * ctxt, xmlChar ** publicId, int strict);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Generated fuzz driver for:
//   xmlChar * xmlParseExternalID(xmlParserCtxt * ctxt, xmlChar ** publicId, int strict);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Notes:
// - This driver sets up a libxml2 parser context and feeds the fuzzer input
//   as the parser input buffer so xmlParseExternalID reads from it.
// - The driver tries both strict = 0 and strict = 1 to exercise both paths.
// - Resources are cleaned up after each run.
//
// Build (example):
//   cc -O2 -g -fsanitize=address,fuzzer -I/path/to/libxml2/include \\
//      fuzz_xmlParseExternalID.c -L/path/to/libxml2/lib -lxml2 -o fuzz_xmlParseExternalID
//
// Adjust include/library paths as needed for your environment.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 public and internal headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlmemory.h>

/* Fuzzer entrypoint expected by libFuzzer / LLVM's fuzzing harness */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 global state (no-op if already initialized) */
    xmlInitParser();

    /* Create a new parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Set a quiet error handler to avoid noisy stderr output while fuzzing.
       We'll rely on the fuzzer detecting crashes rather than text errors. */
    /* If xmlCtxtSetErrorHandler is not available in your build, this call is benign. */
    xmlCtxtSetErrorHandler(ctxt, (xmlStructuredErrorFunc)NULL, NULL);

    /* Create an input buffer from the fuzzer data (in-memory) */
    xmlParserInputBufferPtr inputBuf = xmlParserInputBufferCreateMem((const char *)Data,
                                                                     (int)Size,
                                                                     XML_CHAR_ENCODING_NONE);
    if (inputBuf == NULL) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Create a new input stream and attach the buffer to it.
       This mirrors usages inside libxml2 examples. */
    xmlParserInputPtr inputStream = xmlNewInputStream(ctxt);
    if (inputStream == NULL) {
        /* Clean up buffer */
        xmlFreeParserInputBuffer(inputBuf);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Attach buffer to the input stream */
    inputStream->buf = inputBuf;

    /* Reset the underlying xmlBuf input state so libxml can read from the buffer.
       xmlParserInputBufferCreateMem created inputBuf and its buffer member. */
    if (inputBuf->buffer != NULL) {
        /* xmlBufResetInput is declared in parserInternals.h */
        xmlBufResetInput(inputBuf->buffer, inputStream);
    }

    /* Push the input stream onto the parser context input stack */
    if (xmlCtxtPushInput(ctxt, inputStream) < 0) {
        /* Failed to push input: cleanup */
        /* xmlCtxtPushInput takes ownership on success; on failure free manually */
        xmlFreeInputStream(inputStream);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Prepare storage for publicId returned by xmlParseExternalID */
    xmlChar *publicId = NULL;

    /* Call the target function with strict = 0 (non-strict) */
    /* Protect calls with a basic try: we just call and free any malloced result */
    (void)xmlParseExternalID(ctxt, &publicId, 0);
    if (publicId != NULL) {
        xmlFree(publicId);
        publicId = NULL;
    }

    /* Reset parser input position if possible to allow a second call.
       Easiest approach: reuse the same context but reinitialize input pointers.
       For simplicity, create a fresh parser context and new input so the second
       call starts from the input beginning. */

    /* Pop and free the previous input pushed (xmlFreeParserCtxt will handle most,
       but explicitly pop to be clearer) */
    /* Note: xmlPopInput? Not used here; free the whole parser ctxt and recreate. */

    xmlFreeParserCtxt(ctxt);

    /* Create a fresh context and reattach the same Data as input for strict=1 */
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        /* free the input buffer from earlier path (owned by inputStream) already freed by xmlFreeParserCtxt */
        xmlCleanupParser();
        return 0;
    }

    /* Re-create input buffer and stream for second call */
    inputBuf = xmlParserInputBufferCreateMem((const char *)Data, (int)Size, XML_CHAR_ENCODING_NONE);
    if (inputBuf == NULL) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }
    inputStream = xmlNewInputStream(ctxt);
    if (inputStream == NULL) {
        xmlFreeParserInputBuffer(inputBuf);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }
    inputStream->buf = inputBuf;
    if (inputBuf->buffer != NULL) {
        xmlBufResetInput(inputBuf->buffer, inputStream);
    }
    if (xmlCtxtPushInput(ctxt, inputStream) < 0) {
        xmlFreeInputStream(inputStream);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Call the target function with strict = 1 (strict) */
    (void)xmlParseExternalID(ctxt, &publicId, 1);
    if (publicId != NULL) {
        xmlFree(publicId);
        publicId = NULL;
    }

    /* Cleanup: free parser context which will free remaining inputs */
    xmlFreeParserCtxt(ctxt);

    /* Global cleanup (no-op between runs but good hygiene) */
    xmlCleanupParser();

    return 0;
}