#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Use project headers found in the workspace. Adjust paths if needed. */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"

/*
 * Fuzzer entry point for libFuzzer.
 *
 * This driver creates a memory parser context from the provided input
 * and calls xmlParseXMLDecl() on that context. It appends extra
 * NUL-padding to the input so the parser cannot read past the end
 * of the provided memory (avoids ASan heap-buffer-overflow when
 * parser macros read ahead).
 *
 * Do not change the signature of this function (required by libFuzzer).
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* nothing to do for empty input */
    if (Data == NULL || Size == 0) return 0;

    /* Avoid integer truncation / excessively large sizes */
    if (Size > (size_t)INT_MAX - 16) return 0; /* leave room for padding */

    /* Initialize libxml2 parser machinery */
    xmlInitParser();

    /* Allocate a buffer with extra NUL padding to make reads past 'Size'
       safe for the parser (it often reads ahead without checking length). */
    const int PADDING = 8;
    size_t new_size = Size + PADDING;
    char *buf = (char *)malloc(new_size);
    if (buf == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Copy input and append NULs */
    memcpy(buf, Data, Size);
    memset(buf + Size, 0, PADDING);

    /* Create a parser context that uses the supplied buffer as input.
       We pass the padded length so internal raw reads won't run off the buffer. */
    xmlParserCtxt *ctxt = xmlCreateMemoryParserCtxt((const char *)buf, (int)new_size);
    if (ctxt == NULL) {
        free(buf);
        xmlCleanupParser();
        return 0;
    }

    /* Call the target function under test.
     * xmlParseXMLDecl expects the buffer to be positioned at "<?xml",
     * but we call it on arbitrary data to fuzz internal parsing logic.
     */
    xmlParseXMLDecl(ctxt);

    /* Clean up */
    xmlFreeParserCtxt(ctxt);
    free(buf);
    xmlCleanupParser();

    return 0;
}
