#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlmemory.h>

#ifdef __cplusplus
extern "C" {
#endif

// Optional fuzzer initializer
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize the libxml2 parser library.
    xmlInitParser();
    // Disable libxml2 default error reporting to stderr to avoid noise.
    xmlSetGenericErrorFunc(NULL, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // We allow zero-size, but xmlNewStringInputStream expects a C string,
    // so allocate Size+1 and NUL-terminate.
    xmlChar *buf = (xmlChar *)malloc(Size + 1);
    if (buf == NULL) return 0;
    if (Size > 0) memcpy(buf, Data, Size);
    buf[Size] = 0;

    // Create a parser context.
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    // Create a new input stream from the provided buffer.
    // xmlNewStringInputStream does NOT push the input on the ctxt stack,
    // so we must push it explicitly before calling parser routines using CUR.
    xmlParserInputPtr input = xmlNewStringInputStream(ctxt, buf);

    // If input creation failed, clean up and return.
    if (input == NULL) {
        xmlFreeParserCtxt(ctxt);
        free(buf);
        return 0;
    }

    // Push the input into the context so ctxt->input and CUR are valid.
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        // push failed: clean up
        xmlFreeInputStream(input);
        xmlFreeParserCtxt(ctxt);
        free(buf);
        return 0;
    }

    // Call the function under test.
    // xmlParseVersionNum will read from ctxt->input via parser macros.
    xmlChar *version = xmlParseVersionNum(ctxt);
    if (version != NULL) {
        xmlFree(version);
    }

    // Pop the input from the context and free it.
    // xmlCtxtPopInput returns the popped input pointer.
    xmlParserInputPtr popped = xmlCtxtPopInput(ctxt);
    if (popped != NULL) {
        xmlFreeInputStream(popped);
    }

    // Clean up parser context.
    xmlFreeParserCtxt(ctxt);

    // Free our allocated copy of the fuzzer data.
    free(buf);

    // Clear any stored libxml errors (safe to call if available).
    xmlResetLastError();

    return 0;
}

#ifdef __cplusplus
}
#endif