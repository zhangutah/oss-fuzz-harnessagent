#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Use project header discovered for xmlParseName + input helpers */
#include "/src/libxml2/include/libxml/parserInternals.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* No input -> nothing to do */
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser globals (safe to call multiple times). */
    xmlInitParser();

    /* Create a new parser context. */
    xmlParserCtxt *ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Copy the fuzz data into a null-terminated buffer because
       xmlNewStringInputStream / xmlCtxtNewInputFromString expect C strings. */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Create a new input stream from the string. */
    xmlParserInputPtr input = xmlNewStringInputStream(ctxt, (const xmlChar *)buf);
    if (input == NULL) {
        free(buf);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Push the input onto the parser context input stack so ctxt->input is valid.
       xmlNewStringInputStream does not automatically attach the input to ctxt->input. */
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        /* attaching failed; free the input and cleanup */
        xmlFreeInputStream(input);
        free(buf);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Call the target function under test. */
    const xmlChar *name = xmlParseName(ctxt);

    /* Use the result in a benign way to avoid compiler optimizing it out. */
    if (name != NULL) {
        /* Access first byte safely */
        volatile unsigned char c = name[0];
        (void)c;
    }

    /* Clean up. xmlFreeParserCtxt will free the input streams attached to the context. */
    xmlFreeParserCtxt(ctxt);
    free(buf);

    (void)name;
    return 0;
}
