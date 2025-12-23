#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 Use the public libxml2 headers for xmlChar, xmlFree, etc.
 These should be found via the build include paths (e.g., -I../include).
*/
#include <libxml/xmlstring.h>
#include <libxml/xmlmemory.h>

/*
 The private header private/io.h defines XML_ESCAPE_* macros and
 declared xmlEscapeText() with XML_HIDDEN visibility annotations.
 To avoid depending on XML_HIDDEN we:
  - locally define the XML_ESCAPE_* macros with the same values
  - declare the xmlEscapeText() prototype here
*/

/* same values as in libxml2/include/private/io.h */
#ifndef XML_ESCAPE_ATTR
#define XML_ESCAPE_ATTR             (1u << 0)
#endif
#ifndef XML_ESCAPE_NON_ASCII
#define XML_ESCAPE_NON_ASCII        (1u << 1)
#endif
#ifndef XML_ESCAPE_HTML
#define XML_ESCAPE_HTML             (1u << 2)
#endif
#ifndef XML_ESCAPE_QUOT
#define XML_ESCAPE_QUOT             (1u << 3)
#endif

/* Declare the function under test (definition lives in the library). */
xmlChar *xmlEscapeText(const xmlChar *text, int flags);

/*
 Fuzzer entry point called by libFuzzer / OSS-Fuzz harness.
 This will:
  - construct a nul-terminated xmlChar* string from the input bytes,
  - pick flags derived from the input,
  - call xmlEscapeText,
  - free the returned buffer with xmlFree if non-NULL,
  - free the temporary input buffer and return.
*/
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Limit the size we copy to avoid excessive allocation from huge inputs */
    size_t copy_size = Size;
    const size_t MAX_COPY = 1 << 20; /* 1 MiB */
    if (copy_size > MAX_COPY)
        copy_size = MAX_COPY;

    /* Create a nul-terminated xmlChar buffer */
    xmlChar *buf = (xmlChar *)malloc(copy_size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, copy_size);
    buf[copy_size] = '\0';

    /* Derive flags from the first byte of input to explore variations. */
    int flags = 0;
    uint8_t first = Data[0];
    if (first & 0x01)
        flags |= XML_ESCAPE_NON_ASCII;
    if (first & 0x02)
        flags |= XML_ESCAPE_HTML;
    if (first & 0x04)
        flags |= XML_ESCAPE_QUOT;

    switch ((first >> 3) & 0x7) {
        case 1: flags = 0; break;
        case 2: flags = XML_ESCAPE_QUOT; break;
        case 3: flags = XML_ESCAPE_NON_ASCII; break;
        case 4: flags = XML_ESCAPE_HTML; break;
        case 5: flags = XML_ESCAPE_HTML | XML_ESCAPE_QUOT; break;
        default: /* keep current flags */ break;
    }

    /* Call the target function under test */
    xmlChar *escaped = xmlEscapeText((const xmlChar *)buf, flags);

    /* Free returned buffer if allocation succeeded */
    if (escaped != NULL) {
        xmlFree(escaped);
    }

    free(buf);
    return 0;
}
