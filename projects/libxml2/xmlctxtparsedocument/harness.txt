#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Public libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>

/* Internal header needed for xmlNewStringInputStream declaration */
#include <libxml/parserInternals.h>

/*
 * Fuzzer entry point.
 *
 * This fuzz driver constructs an xmlParserCtxt, creates an input stream
 * from the provided fuzz bytes, calls xmlCtxtParseDocument(ctxt, input)
 * and frees resources. xmlCtxtParseDocument will consume and free the
 * pushed input stream, but we must free the returned document and the
 * parser context.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Avoid pathological huge allocations from fuzzer inputs */
    const size_t MAX_INPUT_BYTES = 10 * 1024 * 1024; /* 10 MB */
    if (Data == NULL || Size == 0)
        return 0;
    if (Size > MAX_INPUT_BYTES)
        Size = MAX_INPUT_BYTES;

    /* Initialize libxml2 once per process (cheap to call repeatedly too) */
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        inited = 1;
    }

    /* Create a parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Copy data into a NUL-terminated buffer expected by the string input helper */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Create an input stream from the string buffer.
     * xmlNewStringInputStream takes xmlChar* and the parser context.
     */
    xmlParserInputPtr input = xmlNewStringInputStream(ctxt, (const xmlChar *)buf);

    /* We can free our copy of the data right away; the input stream
     * created by xmlNewStringInputStream copies or references it as needed.
     */
    free(buf);

    if (input != NULL) {
        /* Call the function under test */
        xmlDocPtr doc = xmlCtxtParseDocument(ctxt, input);

        /* xmlCtxtParseDocument pops/frees any remaining input streams.
         * If a document was produced, free it.
         */
        if (doc != NULL)
            xmlFreeDoc(doc);
    }

    /* Free the parser context (this will free internal state) */
    xmlFreeParserCtxt(ctxt);

    /* We don't call xmlCleanupParser() here because libFuzzer runs multiple
     * inputs in the same process and global cleanup may interfere with later runs.
     */

    return 0;
}