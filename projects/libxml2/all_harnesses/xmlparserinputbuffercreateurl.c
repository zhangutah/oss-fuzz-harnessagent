#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Public libxml headers for the needed types and helpers */
#include <libxml/encoding.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlerror.h>
#include <libxml/parser.h> /* <-- Added to define xmlParserInputFlags */

/*
 * The target function is internal (declared in private/io.h), so provide
 * a compatible prototype here so the harness can call it.
 *
 * xmlParserErrors xmlParserInputBufferCreateUrl(const char * URI,
 *     xmlCharEncoding enc, xmlParserInputFlags flags, xmlParserInputBuffer ** out);
 */
extern xmlParserErrors
xmlParserInputBufferCreateUrl(const char *URI, xmlCharEncoding enc,
                              xmlParserInputFlags flags,
                              xmlParserInputBuffer **out);

/*
 * Fuzzer entry point for:
 * xmlParserErrors xmlParserInputBufferCreateUrl(const char * URI,
 *     xmlCharEncoding enc, xmlParserInputFlags flags, xmlParserInputBuffer ** out);
 *
 * The fuzzer interprets the input bytes as:
 *  - byte 0: xmlCharEncoding value (cast)
 *  - bytes 1..4: flags (uint32_t little-endian)
 *  - remaining bytes: URI (NUL-terminated)
 *
 * If the URI length is zero, an empty string is passed.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Minimum header: 1 byte for enc. If available, use next 4 bytes for flags. */
    size_t offset = 1;
    xmlCharEncoding enc = (xmlCharEncoding)Data[0];

    uint32_t flags = 0;
    if (Size >= 5) {
        /* Read 4 bytes little-endian into flags */
        flags = (uint32_t)Data[1] |
                ((uint32_t)Data[2] << 8) |
                ((uint32_t)Data[3] << 16) |
                ((uint32_t)Data[4] << 24);
        offset = 5;
    } else {
        /* If not enough bytes, default flags to 0 */
        flags = 0;
        offset = 1;
    }

    size_t uri_len = 0;
    if (Size > offset)
        uri_len = Size - offset;
    else
        uri_len = 0;

    /* Cap URI size to avoid extremely large allocations from malformed corpora */
    const size_t MAX_URI = 1 << 20; /* 1 MiB */
    if (uri_len > MAX_URI)
        uri_len = MAX_URI;

    char *uri = (char *)malloc(uri_len + 1);
    if (uri == NULL)
        return 0;

    if (uri_len > 0)
        memcpy(uri, Data + offset, uri_len);
    uri[uri_len] = '\0';

    xmlParserInputBuffer *out = NULL;

    /* Call the target function */
    (void)xmlParserInputBufferCreateUrl(uri, enc, (xmlParserInputFlags)flags, &out);

    /* Clean up any allocated parser input buffer returned by the function */
    if (out != NULL) {
        xmlFreeParserInputBuffer(out);
        out = NULL;
    }

    free(uri);
    return 0;
}