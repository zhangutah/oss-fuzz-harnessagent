// Fixed fuzz driver for: void xmlParseEntityDecl(xmlParserCtxt *ctxt);
// Fuzzer entry: int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Core libxml2 headers */
#include <libxml/parser.h>
/* Internal declaration for xmlParseEntityDecl */
#include "/src/libxml2/include/libxml/parserInternals.h"

/*
 * Ensure ATTRIBUTE_UNUSED is defined if not provided by build system.
 * Some build environments define ATTRIBUTE_UNUSED elsewhere; when it's not
 * defined in this translation unit the raw token caused a parse error.
 */
#ifndef ATTRIBUTE_UNUSED
#if defined(__GNUC__) || defined(__clang__)
#define ATTRIBUTE_UNUSED __attribute__((unused))
#else
#define ATTRIBUTE_UNUSED
#endif
#endif

/* Optional fuzzer initialization. Called by libFuzzer before fuzzing. */
int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    /*
     * Initialize the libxml2 parser library. This sets up global tables
     * and data structures the parser may rely on.
     */
    xmlInitParser();
    /* Disable allocator hooks here if needed, or set custom error handlers. */
    return 0;
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    xmlParserCtxtPtr ctxt = NULL;
    xmlChar *buffer = NULL;

    /* Require at least one byte so xmlCreateDocParserCtxt has something meaningful. */
    if (Data == NULL || Size == 0)
        return 0;

    /* Create a NUL-terminated copy of the input for libxml2 (xmlChar is unsigned char). */
    buffer = (xmlChar *)malloc(Size + 1);
    if (buffer == NULL)
        return 0;
    memcpy(buffer, Data, Size);
    buffer[Size] = 0;

    /*
     * Create a parser context initialized with the buffer.
     * xmlCreateDocParserCtxt sets up the input stack so xmlParseEntityDecl
     * can operate on the current input.
     */
    ctxt = xmlCreateDocParserCtxt(buffer);
    if (ctxt == NULL) {
        free(buffer);
        return 0;
    }

    /*
     * Call the target function under fuzz control.
     * xmlParseEntityDecl is an internal parsing routine that expects the
     * parser context to be ready (input stream, current pointer, etc.)
     * xmlCreateDocParserCtxt provides that environment.
     */
    xmlParseEntityDecl(ctxt);

    /* Clean up parser context and buffer */
    xmlFreeParserCtxt(ctxt);
    free(buffer);

    /* Reset any global last error to avoid leak of state between runs */
    xmlResetLastError();

    return 0;
}
