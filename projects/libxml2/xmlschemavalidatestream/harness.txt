#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "/src/libxml2/include/libxml/xmlschemas.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /*
     * Initialize libxml parser library (no-op if already initialized).
     * It's safe to call on every fuzz input.
     */
    xmlInitParser();

    /*
     * Create a minimal, valid empty XML Schema so we can obtain a
     * xmlSchemaValidCtxt to pass to xmlSchemaValidateStream.
     */
    const char *schemaStr = "<xs:schema xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"/>";

    xmlSchemaParserCtxtPtr pctxt = xmlSchemaNewMemParserCtxt(schemaStr, (int)strlen(schemaStr));
    if (pctxt == NULL) {
        return 0;
    }

    xmlSchemaPtr schema = xmlSchemaParse(pctxt);
    if (schema == NULL) {
        xmlSchemaFreeParserCtxt(pctxt);
        return 0;
    }

    xmlSchemaValidCtxtPtr vctxt = xmlSchemaNewValidCtxt(schema);
    if (vctxt == NULL) {
        xmlSchemaFree(schema);
        xmlSchemaFreeParserCtxt(pctxt);
        return 0;
    }

    /*
     * Write the fuzz input to a temporary file and create an
     * xmlParserInputBuffer from that filename. This avoids trying to
     * construct xmlParserInputBuffer internals manually.
     */
    char tmpname[] = "/tmp/libxml_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        xmlSchemaFreeValidCtxt(vctxt);
        xmlSchemaFree(schema);
        xmlSchemaFreeParserCtxt(pctxt);
        return 0;
    }

    /* Write the input bytes to the temp file */
    ssize_t to_write = (ssize_t)Size;
    const uint8_t *bufptr = Data;
    while (to_write > 0) {
        ssize_t wrote = write(fd, bufptr, (size_t)to_write);
        if (wrote <= 0) break;
        to_write -= wrote;
        bufptr += wrote;
    }
    close(fd);

    /* Create parser input buffer from the temporary filename */
    xmlParserInputBufferPtr inputBuf = xmlParserInputBufferCreateFilename(tmpname, XML_CHAR_ENCODING_NONE);
    if (inputBuf != NULL) {
        /* Call the target function. Pass NULL for sax and user_data. */
        (void)xmlSchemaValidateStream(vctxt, inputBuf, XML_CHAR_ENCODING_NONE, NULL, NULL);

        /*
         * NOTE: Do NOT call xmlFreeParserInputBuffer(inputBuf) here.
         * xmlSchemaValidateStream takes ownership / may free the buffer;
         * freeing it again causes use-after-free / double free.
         */
    }

    /* Cleanup temporary file */
    unlink(tmpname);

    /* Free validation and parsing resources */
    xmlSchemaFreeValidCtxt(vctxt);
    xmlSchemaFree(schema);
    xmlSchemaFreeParserCtxt(pctxt);

    /* Note: not calling xmlCleanupParser() to avoid expensive teardown
     * on each iteration; the harness environment can call that at exit.
     */

    return 0;
}
