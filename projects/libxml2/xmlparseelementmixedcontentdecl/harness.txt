#ifndef XML_DEPRECATED
#define XML_DEPRECATED
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Provide ATTRIBUTE_UNUSED if not already defined to avoid parse errors. */
#ifndef ATTRIBUTE_UNUSED
#if defined(__GNUC__) || defined(__clang__)
#define ATTRIBUTE_UNUSED __attribute__((unused))
#else
#define ATTRIBUTE_UNUSED
#endif
#endif

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include <libxml/valid.h>
#include <libxml/xmlerror.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Optional fuzz initialization hook called by libFuzzer before fuzzing starts. */
int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    /* Initialize parser globals (thread once). */
    xmlInitParser();

    /* Quiet libxml error messages for fuzzing runs. */
    xmlSetGenericErrorFunc(NULL, NULL);

    return 0;
}

/* Fuzzer entry point. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Reject extremely large inputs to avoid huge allocations in the harness. */
    const size_t MAX_FUZZ_INPUT = 200000;
    if (Size == 0 || Size > MAX_FUZZ_INPUT)
        return 0;

    /* Create a new parser context. */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Create a parser input buffer from the provided memory.
     * xmlParserInputBufferCreateMem expects a const char* and an int size.
     */
    xmlParserInputBufferPtr buf = xmlParserInputBufferCreateMem((const char *)Data, (int)Size, XML_CHAR_ENCODING_NONE);
    if (buf == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Create a new xmlParserInput from the buffer (does not push it on the ctxt). */
    xmlParserInputPtr input = xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE);
    if (input == NULL) {
        /* xmlNewIOInputStream did not take ownership; free the buffer. */
        xmlFreeParserInputBuffer(buf);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Push the input on the parser context input stack. */
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        /* Failed to push: free input and context. */
        xmlFreeInputStream(input);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* openInputNr should be the input index corresponding to the entity being parsed.
     * Use the current input number from the context.
     */
    int openInputNr = ctxt->inputNr;

    /* Call the target function. */
    xmlElementContent * result = NULL;
    /* Protect against parser stop flags; call directly. */
    result = xmlParseElementMixedContentDecl(ctxt, openInputNr);

    /* Free returned structure if any. */
    if (result != NULL) {
        xmlFreeElementContent(result);
    }

    /* Clean up input(s) and context.
     * xmlFreeParserCtxt will free remaining resources and any inputs pushed on the context.
     * Do NOT free the input here again, as it was pushed onto the context and is owned
     * by the parser context (freeing it here would cause a double-free / use-after-free).
     */

    /* Free the parser context and associated resources. */
    xmlFreeParserCtxt(ctxt);

    /* Reset last error for next run. */
    xmlResetLastError();

    return 0;
}

#ifdef __cplusplus
}
#endif