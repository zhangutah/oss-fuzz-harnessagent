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
// //xmlSetDeclaredEncoding(xmlParserCtxt *ctxt, xmlChar *encoding) {
// //    if (((ctxt->input->flags & XML_INPUT_HAS_ENCODING) == 0) &&
// //        ((ctxt->options & XML_PARSE_IGNORE_ENC) == 0)) {
// //        xmlCharEncodingHandlerPtr handler;
// //        xmlParserErrors res;
// //        xmlCharEncFlags flags = XML_ENC_INPUT;
// //
// //        /*
// //         * xmlSwitchEncodingName treats unsupported encodings as
// //         * warnings, but we want it to be an error in an encoding
// //         * declaration.
// //         */
// //        if (ctxt->html)
// //            flags |= XML_ENC_HTML;
// //        res = xmlCreateCharEncodingHandler((const char *) encoding,
// //                flags, ctxt->convImpl, ctxt->convCtxt, &handler);
// //        if (res != XML_ERR_OK) {
// //            xmlFatalErr(ctxt, res, (const char *) encoding);
// //            xmlFree(encoding);
// //            return;
// //        }
// //
// //        res  = xmlInputSetEncodingHandler(ctxt->input, handler);
// //        if (res != XML_ERR_OK) {
// //            xmlCtxtErrIO(ctxt, res, NULL);
// //            xmlFree(encoding);
// //            return;
// //        }
// //
// //        ctxt->input->flags |= XML_INPUT_USES_ENC_DECL;
// //    } else if (ctxt->input->flags & XML_INPUT_AUTO_ENCODING) {
// //        static const char *allowedUTF8[] = {
// //            "UTF-8", "UTF8", NULL
// //        };
// //        static const char *allowedUTF16LE[] = {
// //            "UTF-16", "UTF-16LE", "UTF16", NULL
// //        };
// //        static const char *allowedUTF16BE[] = {
// //            "UTF-16", "UTF-16BE", "UTF16", NULL
// //        };
// //        const char **allowed = NULL;
// //        const char *autoEnc = NULL;
// //
// //        switch (ctxt->input->flags & XML_INPUT_AUTO_ENCODING) {
// //            case XML_INPUT_AUTO_UTF8:
// //                allowed = allowedUTF8;
// //                autoEnc = "UTF-8";
// //                break;
// //            case XML_INPUT_AUTO_UTF16LE:
// //                allowed = allowedUTF16LE;
// //                autoEnc = "UTF-16LE";
// //                break;
// //            case XML_INPUT_AUTO_UTF16BE:
// //                allowed = allowedUTF16BE;
// //                autoEnc = "UTF-16BE";
// //                break;
// //        }
// //
// //        if (allowed != NULL) {
// //            const char **p;
// //            int match = 0;
// //
// //            for (p = allowed; *p != NULL; p++) {
// //                if (xmlStrcasecmp(encoding, BAD_CAST *p) == 0) {
// //                    match = 1;
// //                    break;
// //                }
// //            }
// //
// //            if (match == 0) {
// //                xmlWarningMsg(ctxt, XML_WAR_ENCODING_MISMATCH,
// //                              "Encoding '%s' doesn't match "
// //                              "auto-detected '%s'\n",
// //                              encoding, BAD_CAST autoEnc);
// //                xmlFree(encoding);
// //                encoding = xmlStrdup(BAD_CAST autoEnc);
// //                if (encoding == NULL)
// //                    xmlCtxtErrMemory(ctxt);
// //            }
// //        }
// //    }
// //
// //    if (ctxt->encoding != NULL)
// //        xmlFree(ctxt->encoding);
// //    ctxt->encoding = encoding;
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlParserErrors xmlInputSetEncodingHandler(xmlParserInput * input, xmlCharEncodingHandler * handler);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   xmlParserErrors xmlInputSetEncodingHandler(xmlParserInput * input, xmlCharEncodingHandler * handler);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver:
// - Creates an xmlParserInput from the fuzzer data (memory input).
// - Attempts to open/create an encoding handler with the fuzzer data as the
//   encoding name.
// - Calls xmlInputSetEncodingHandler(input, handler).
// - Cleans up resources carefully (avoid double-closing the handler if it was
//   attached to the input buffer).
//
// Note: Uses absolute project headers as requested.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Absolute include paths from the project (requested). */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/encoding.h"
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/xmlIO.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Initialize libxml (no-op if already initialized). */
    xmlInitParser();

    /* Prepare a NUL-terminated copy of the fuzzer data to use as encoding name. */
    size_t name_len = (Size > 4096) ? 4096 : Size; /* limit name length a bit */
    char *encname = (char *)malloc(name_len + 1);
    if (encname == NULL) return 0;
    if (name_len > 0) memcpy(encname, Data, name_len);
    encname[name_len] = '\0';

    /* Prepare memory for xmlNewInputFromMemory.
       If Size == 0, pass a pointer to an empty string (xmlNewInputFromMemory
       requires non-NULL mem). */
    const void *mem_ptr = (Size == 0) ? (const void *)"" : (const void *)Data;
    size_t mem_size = Size;

    /* Create a parser input from the fuzzer-provided memory. */
    xmlParserInput *input = xmlNewInputFromMemory("fuzz", mem_ptr, mem_size, 0);

    /* Create/open an encoding handler from the encoding name (may return NULL
       handler for UTF-8 or on error). */
    xmlCharEncodingHandler *handler = NULL;
    /* Use xmlOpenCharEncodingHandler which returns an xmlParserErrors code and
       fills handler pointer. Provide output=0 to ask for input conversion handler. */
    (void)xmlOpenCharEncodingHandler(encname, 0, &handler);

    /* Call the function under test. It's safe to pass NULL for input or handler. */
    (void)xmlInputSetEncodingHandler(input, handler);

    /*
     * Cleanup:
     * - If handler is non-NULL and was NOT attached to input->buf->encoder,
     *   close it here with xmlCharEncCloseFunc(handler).
     * - Free the input via xmlFreeInputStream(input).
     *
     * Be careful to avoid double-closing the handler: xmlInputSetEncodingHandler
     * sets input->buf->encoder = handler on success, and takes ownership.
     */
    if (handler != NULL) {
        int handler_owned_by_input = 0;
        if (input != NULL) {
            /* input->buf is an xmlParserInputBufferPtr; check its encoder field. */
            xmlParserInputBuffer *inbuf = input->buf;
            if (inbuf != NULL && inbuf->encoder == handler)
                handler_owned_by_input = 1;
        }
        if (!handler_owned_by_input) {
            /* Not attached to the input buffer: safe to close it here. */
            xmlCharEncCloseFunc(handler);
        }
    }

    if (input != NULL) {
        xmlFreeInputStream(input);
    }

    free(encname);

    /* Optional: cleanup global parser state (safe to call). */
    /* xmlCleanupParser();  -- avoid calling repeatedly in some harnesses */

    return 0;
}
