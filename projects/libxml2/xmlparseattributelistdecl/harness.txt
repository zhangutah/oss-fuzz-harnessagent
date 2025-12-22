#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef ATTRIBUTE_UNUSED
# if defined(__GNUC__) || defined(__clang__)
#  define ATTRIBUTE_UNUSED __attribute__((unused))
# else
#  define ATTRIBUTE_UNUSED
# endif
#endif

#include <libxml/parser.h>
#include <libxml/parserInternals.h> /* declaration of xmlParseAttributeListDecl and internals */
#include <libxml/xmlversion.h>
#include <libxml/xmlerror.h>

#ifdef __cplusplus
extern "C" {
#endif

// Optional initializer called by libFuzzer at startup.
int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    /*
     * Initialize the libxml2 library. This sets up internal state used by the
     * parser. It's safe to call multiple times.
     */
    xmlInitParser();
    /* Clear any previous errors. */
    xmlResetLastError();
    return 0;
}

/*
 * Fuzzer entry point. Creates an xmlParserCtxt, wraps the input bytes into a
 * libxml2 input stream using xmlNewStringInputStream and calls
 * xmlParseAttributeListDecl(ctxt).
 *
 * The function returns 0 per libFuzzer conventions.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    xmlParserCtxtPtr ctxt = NULL;
    xmlChar *buf = NULL;
    const size_t MAX_ALLOC = 10 * 1024 * 1024; /* 10MB cap */

    if (Data == NULL || Size == 0)
        return 0;

    /* Avoid excessive allocations from malformed drivers. */
    if (Size > MAX_ALLOC)
        Size = MAX_ALLOC;

    /* Make a nul-terminated copy of the input for xmlNewStringInputStream. */
    buf = (xmlChar *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Ensure libxml2 global initialization is done (idempotent). */
    xmlInitParser();

    /* Create a new parser context. */
    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /*
     * Create a string input stream for the parser context.
     * xmlNewStringInputStream returns a new xmlParserInputPtr but does not
     * automatically push it on the context's input stack. Push it explicitly.
     */
    xmlParserInputPtr input = xmlNewStringInputStream(ctxt, buf);
    if (input == NULL) {
        xmlFreeParserCtxt(ctxt);
        free(buf);
        return 0;
    }
    if (xmlPushInput(ctxt, input) < 0) {
        /* push failed, free the input and bail out */
        xmlFreeInputStream(input);
        xmlFreeParserCtxt(ctxt);
        free(buf);
        return 0;
    }

    /* Call the targeted internal function under test. */
    xmlParseAttributeListDecl(ctxt);

    /* Clean up. xmlFreeParserCtxt will free the input stack too. */
    xmlFreeParserCtxt(ctxt);

    /* Free the duplicated input buffer. */
    free(buf);

    /* Reset the last error state so subsequent runs are clean. */
    xmlResetLastError();

    return 0;
}

#ifdef __cplusplus
}
#endif
