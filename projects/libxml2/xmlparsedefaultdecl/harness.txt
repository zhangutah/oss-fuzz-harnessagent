#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Use project headers found by inspection */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/xmlerror.h"

/*
  Fuzz driver for:
    int xmlParseDefaultDecl(xmlParserCtxt * ctxt, xmlChar ** value);

  This driver creates a minimal xmlParserCtxt and xmlParserInput that point
  into a buffer derived from the fuzzer input and calls xmlParseDefaultDecl.
  Allocated resources are freed before returning.
*/

/* Minimal structured error handler to prevent xmlCtxtVErr from dereferencing
   ctxt->sax when it's NULL. */
static void
fuzz_structured_error(void *userData, xmlErrorPtr error) {
    (void)userData;
    (void)error;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Initialize libxml once (safe to call repeatedly) */
    xmlInitParser();

    /* Allocate and zero a parser context */
    xmlParserCtxt *ctxt = (xmlParserCtxt *)calloc(1, sizeof(xmlParserCtxt));
    if (ctxt == NULL) return 0;

    /* Install a minimal error handler so xmlCtxtVErr won't dereference NULL sax. */
    ctxt->errorHandler = fuzz_structured_error;
    ctxt->errorCtxt = NULL;

    /* Make sure inputNr is consistent (1 input attached). */
    ctxt->inputNr = 1;

    /* Allocate and prepare an xmlParserInput */
    xmlParserInput *in = (xmlParserInput *)calloc(1, sizeof(xmlParserInput));
    if (in == NULL) {
        free(ctxt);
        return 0;
    }

    /* Copy fuzzer data into a nul-terminated xmlChar buffer */
    xmlChar *buffer = (xmlChar *)malloc(Size + 1);
    if (buffer == NULL) {
        free(in);
        free(ctxt);
        return 0;
    }
    memcpy(buffer, Data, Size);
    buffer[Size] = 0; /* null-terminate for safety */

    /* Point the parser input window into our buffer */
    in->base = buffer;
    in->cur  = buffer;
    in->end  = buffer + Size; /* parsing macros use end as limit */

    /* Set safe defaults for line/col to avoid reading uninitialized data. */
    in->line = 1;
    in->col = 1;
    in->buf = NULL;
    /* encoding is a pointer in xmlParserInput; set to NULL rather than an enum. */
    in->encoding = NULL;
    in->consumed = 0;
    in->filename = NULL; /* keep filename NULL to exercise the error path */

    /* Attach input to context */
    ctxt->input = in;
    /* Zero other fields (calloc already zeroed) - set minimal sensible defaults */
    ctxt->inSubset = 0;
    /* ctxt->replaceEntities is deprecated and already zero from calloc; skip assigning */
    ctxt->errNo = 0;
    ctxt->wellFormed = 1;
    ctxt->disableSAX = 0;
    ctxt->nbErrors = 0;
    ctxt->nbWarnings = 0;
    ctxt->vctxt.userData = NULL;
    ctxt->vctxt.error = NULL;
    ctxt->vctxt.warning = NULL;

    /* Call the target function */
    xmlChar *value = NULL;
    (void)xmlParseDefaultDecl(ctxt, &value);

    /* Free any value returned by the parser */
    if (value != NULL) {
        xmlFree(value);
        value = NULL;
    }

    /* Reset any last error allocated by libxml2 so we don't leak memory. */
    /* Use the context-specific reset so errors allocated into ctxt->lastError are freed. */
    xmlCtxtResetLastError(ctxt);

    /* Clean up our allocations */
    /* Note: xmlParserInput.free is not set; free owned buffers ourselves */
    free(buffer);
    free(in);
    free(ctxt);

    /* It's OK to not call xmlCleanupParser() on every iteration; skip here */

    return 0;
}