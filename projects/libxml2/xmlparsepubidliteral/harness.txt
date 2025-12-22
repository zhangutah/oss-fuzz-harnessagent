#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include libxml2 headers (project absolute paths discovered in the workspace) */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/parserInternals.h"

/* private headers may use XML_HIDDEN (visibility macro). Ensure it's defined
   before including private headers so the compiler sees a valid token. */
#ifndef XML_HIDDEN
#define XML_HIDDEN
#endif

#include "/src/libxml2/include/private/buf.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive checks */
    if (Data == NULL) return 0;

    /* Initialize parser globals (idempotent) */
    xmlInitParser();

    /* Create a new parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) return 0;

    /* Create a parser input buffer that wraps the fuzzer data.
       xmlParserInputBufferCreateMem accepts a const char* and an int size. */
    xmlParserInputBufferPtr ibuf = xmlParserInputBufferCreateMem((const char *)Data,
                                                                 (int)Size,
                                                                 XML_CHAR_ENCODING_NONE);
    if (ibuf == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Create a new input stream for the context */
    xmlParserInputPtr input = xmlNewInputStream(ctxt);
    if (input == NULL) {
        xmlFreeParserInputBuffer(ibuf);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Attach the buffer to the input and reset the buffer input pointers */
    input->buf = ibuf;

    /* xmlBufResetInput updates the parser input using the internal buffer object
       exposed by ibuf->buffer. This sets up input->cur and related fields. */
    if (ibuf->buffer != NULL) {
        (void)xmlBufResetInput(ibuf->buffer, input);
    }

    /* Push the input on the context input stack so macros like CUR/RAW work. */
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        /* Push failed; free resources */
        xmlFreeInputStream(input);
        xmlFreeParserInputBuffer(ibuf);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Call the target function. It returns an xmlChar* which we must free if non-NULL. */
    xmlChar *res = xmlParsePubidLiteral(ctxt);
    if (res != NULL) {
        xmlFree(res);
    }

    /* Clean up parser context which will free remaining inputs/resources. */
    xmlFreeParserCtxt(ctxt);

    /* Note: don't call xmlCleanupParser() here: it's usually done at process exit. */
    return 0;
}
