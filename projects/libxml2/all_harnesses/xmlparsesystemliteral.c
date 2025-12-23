#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Prefer project absolute header path as located in the workspace */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include <libxml/parser.h>

/*
 * Fuzzer entry point.
 *
 * This driver creates a parser context, wraps the fuzzer input into
 * a string input stream and calls xmlParseSystemLiteral(xmlParserCtxt*).
 *
 * Cleanup is performed after the call.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* initialize libxml once (safe to call multiple times) */
    xmlInitParser();

    /* Create a new parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Limit allocation to avoid pathological huge allocations from fuzzer */
    const size_t MAX_ALLOC = 1 << 20; /* 1 MiB */
    size_t useSize = Size;
    if (useSize > MAX_ALLOC) useSize = MAX_ALLOC;

    /* Allocate a nul-terminated buffer for xmlNewStringInputStream */
    xmlChar *buf = (xmlChar *)malloc(useSize + 1);
    if (buf == NULL) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    if (Data != NULL && Size > 0) {
        memcpy(buf, Data, useSize);
    }
    buf[useSize] = '\0'; /* ensure termination */

    /* Create a new string input stream from the buffer */
    xmlParserInputPtr input = xmlNewStringInputStream(ctxt, buf);
    if (input == NULL) {
        free(buf);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Ensure the input is attached to the context input stack.
     * xmlCtxtPushInput is a function (not a macro). Call it directly.
     * If it fails, fall back to assigning ctxt->input to avoid a NULL deref
     * inside xmlParseSystemLiteral.
     */
    int push_ret = -1;
    /* xmlCtxtPushInput is declared in parserInternals.h */
    push_ret = xmlCtxtPushInput(ctxt, input);
    if (push_ret < 0) {
        /* Best-effort fallback so parsing functions see an input */
        if (ctxt->input == NULL) {
            ctxt->input = input;
        }
    }

    /* Call the target function */
    xmlChar *res = xmlParseSystemLiteral(ctxt);

    /* Free the result if any */
    if (res != NULL) {
        xmlFree(res);
    }

    /* Cleanup input/context/buffer
     *
     * Important: ownership of 'buf' is transferred to the xmlParserInput
     * created by xmlNewStringInputStream in many cases (the input's free
     * callback will free it). The parser context cleanup (xmlFreeParserCtxt)
     * will free the input(s) and any associated buffers it owns. To avoid
     * double-free / use-after-free, do not call xmlFreeInputStream(input)
     * here (xmlFreeParserCtxt will free input). Instead, detect whether
     * libxml took ownership (input->free != NULL) and only free 'buf'
     * ourselves if it did not.
     */
    int libxml_owned_buf = 0;
    if (input != NULL && input->free != NULL) {
        libxml_owned_buf = 1;
    }

    /* Freeing the parser context will free the input and possibly the buffer */
    xmlFreeParserCtxt(ctxt);

    /* If libxml did NOT take ownership of buf, free it here. */
   if (!libxml_owned_buf) {
       free(buf);
   }

   /* global cleanup (safe to call repeatedly) */
   xmlCleanupParser();

   return 0;
}