#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <libxml/xmlreader.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

/*
 * Fuzz driver for:
 *   int xmlReaderNewMemory(xmlTextReader * reader,
 *                          const char * buffer,
 *                          int size,
 *                          const char * URL,
 *                          const char * encoding,
 *                          int options);
 *
 * The fuzzer entry point:
 *   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 *
 * Strategy:
 * - Allocate a temporary buffer and copy the fuzzer input into it.
 * - Use xmlReaderForMemory() to obtain an xmlTextReader * from the buffer.
 * - Call xmlReaderNewMemory() (the target) with that reader to ensure the
 *   target function is exercised.
 * - Call xmlTextReaderRead() and a couple of accessor functions to traverse
 *   the reader (helps reach more code paths).
 * - Clean up resources.
 *
 * Note: xmlInitParser() is called once lazily to ensure libxml2 is initialized.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    static int parser_inited = 0;
    if (!parser_inited) {
        xmlInitParser();
        parser_inited = 1;
    }

    /* Cap size to INT_MAX because the API expects an int size. */
    int in_size = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Copy input to a modifiable buffer and NUL-terminate to be safe. */
    char *buf = (char *)malloc((size_t)in_size + 1);
    if (!buf)
        return 0;
    memcpy(buf, Data, (size_t)in_size);
    buf[in_size] = '\0';

    /* Use the public constructor that returns an xmlTextReader *. */
    xmlTextReader *reader = xmlReaderForMemory(buf, in_size, NULL, NULL, 0);

    /* If initialization succeeded, exercise the reader a bit. */
    if (reader != NULL) {
        /* Call the target function explicitly to ensure it's executed. */
        int rc = xmlReaderNewMemory(reader, buf, in_size, NULL, NULL, 0);
        (void)rc; /* ignore result; purpose is to call the target */

        /* Drive the reader: read nodes until finished or error. */
        while (xmlTextReaderRead(reader) == 1) {
            /* Touch some accessors to increase coverage. */
            const xmlChar *name = xmlTextReaderConstName(reader);
            const xmlChar *value = xmlTextReaderConstValue(reader);
            const xmlChar *base = xmlTextReaderConstBaseUri(reader);
            (void)name;
            (void)value;
            (void)base;
        }
        /* Close the reader (best-effort cleanup) and free it. */
        xmlTextReaderClose(reader);
        xmlFreeTextReader(reader);
    }

    /* Free allocated resources. */
    free(buf);

    /* Do not call xmlCleanupParser() here: the fuzzer may call this function many times. */
    return 0;
}