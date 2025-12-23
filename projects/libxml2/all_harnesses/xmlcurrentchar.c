#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include the internal parser header that declares xmlCurrentChar and
 * the parser context/input structures.
 *
 * Use the absolute project path discovered in the workspace.
 */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/tree.h"
/* Include error API so we can reset/free the last error allocated by libxml2. */
#include "/src/libxml2/include/libxml/xmlerror.h"

/* Fuzzer entry point expected by libFuzzer. */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/* Ensure INPUT_CHUNK (used by xmlCurrentChar) is satisfied to avoid
 * triggering xmlParserGrow which may try to read from IO buffers.
 *
 * xmlCurrentChar expects ctxt->input, input->cur and input->end to be valid.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Choose a minimum buffer size >= INPUT_CHUNK to avoid xmlParserGrow.
     * INPUT_CHUNK is defined in private/parser.h as 250.
     */
    const size_t MIN_BUF = 256;
    size_t bufsz = (Size >= MIN_BUF) ? Size : MIN_BUF;

    /* Allocate a writable buffer for the parser input window. */
    unsigned char *buf = (unsigned char *)malloc(bufsz);
    if (buf == NULL)
        return 0;

    /* Copy the fuzzer data (or zero-fill if too small). */
    if (Size > 0)
        memcpy(buf, Data, (Size <= bufsz) ? Size : bufsz);
    if (bufsz > Size)
        memset(buf + Size, 0, bufsz - Size);

    /* Allocate and initialize a parser input and a parser context. */
    xmlParserInput *in = (xmlParserInput *)malloc(sizeof(xmlParserInput));
    if (in == NULL) {
        free(buf);
        return 0;
    }
    memset(in, 0, sizeof(*in));

    /* Set base/cur/end to point into our buffer. Use xmlChar (unsigned char). */
    in->base = (const xmlChar *)buf;
    in->cur  = (const xmlChar *)buf;
    in->end  = (const xmlChar *)(buf + bufsz);

    /* Mark input->buf NULL to avoid buffer grow paths that rely on IO callbacks. */
    in->buf = NULL;
    in->line = 1;
    in->col = 1;
    in->length = (int)bufsz;

    /* Initialize a minimal parser context that refers to our input. */
    xmlParserCtxt ctxt;
    memset(&ctxt, 0, sizeof(ctxt));
    ctxt.input = in;

    /* Provide a minimal, valid SAX handler structure so xmlCtxtVErr (and other
     * error/reporting paths) won't dereference a NULL sax pointer.
     * We zero it so all callbacks are NULL which is safe.
     */
    static xmlSAXHandler sax;
    memset(&sax, 0, sizeof(sax));
    ctxt.sax = &sax;

    /* Ensure vctxt fields are initialized (used for validity/dtd errors). */
    ctxt.vctxt.error = NULL;
    ctxt.vctxt.warning = NULL;
    ctxt.vctxt.userData = NULL;

    /* No custom error handler. userData NULL. */
    ctxt.errorHandler = NULL;
    ctxt.errorCtxt = NULL;
    ctxt.userData = NULL;

    /* Provide sensible defaults for other fields used by error/report code. */
    ctxt.inputNr = 1;
    ctxt.inputTab = NULL;
    ctxt.options = 0;
    ctxt.recovery = 1; /* allow recovery so some fatal paths are less abrupt */

    /* Call the target function. Provide a length output variable. */
    int len = 0;
    /* volatile to reduce risk of the compiler optimizing away the call result. */
    volatile int res = xmlCurrentChar(&ctxt, &len);
    (void)res;
    (void)len;

    /* Reset/free any last error allocated by libxml2 to avoid leaks reported by ASan.
     * Must reset both the parser-context lastError and the thread-local last error.
     */
    xmlCtxtResetLastError(&ctxt);
    xmlResetLastError();

    /* Clean up. */
    free(in);
    free(buf);

    return 0;
}
