#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlerror.h>
#include <libxml/tree.h>

#ifndef UNUSED
#define UNUSED
#endif

int LLVMFuzzerInitialize(int *argc UNUSED, char ***argv UNUSED) {
    (void)argc;
    (void)argv;

    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, NULL);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    int bufSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    char *uri = NULL;
    if (Size > 1) {
        size_t ulen = (Size - 1);
        if (ulen > 64) ulen = 64;
        uri = (char *)malloc(ulen + 1);
        if (uri != NULL) {
            memcpy(uri, Data + 1, ulen);
            uri[ulen] = '\0';
        }
    }

    xmlParserInputBufferPtr input =
        xmlParserInputBufferCreateMem((const char *)Data, bufSize, 0);

    if (input == NULL) {
        if (uri) free(uri);
        return 0;
    }

    xmlTextReaderPtr reader = xmlNewTextReader(input, (const char *)uri);

    if (reader == NULL) {
        xmlFreeParserInputBuffer(input);
        if (uri) free(uri);
        return 0;
    }

    for (int i = 0; i < 1024; ++i) {
        int res = xmlTextReaderRead(reader);
        if (res <= 0) break;
    }

    xmlFreeTextReader(reader);
    xmlFreeParserInputBuffer(input);

    if (uri) free(uri);

    return 0;
}
