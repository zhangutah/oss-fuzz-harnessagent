#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/*
 Fuzz driver for:
   int htmlParseContentType(const xmlChar * val, htmlMetaEncodingOffsets * off);

 We avoid including libxml2's private headers (which introduce macros/types like
 XML_HIDDEN, xmlNode, etc.) that may not be available at compile time for this
 standalone harness. Instead we provide minimal local declarations that match
 the function's expected prototype. The real implementation should be linked
 from libxml2 at link time.
*/

/* Minimal types used by htmlParseContentType */
typedef unsigned char xmlChar;

typedef struct {
    size_t start;
    size_t end;
    size_t size;
} htmlMetaEncodingOffsets;

/* Declare the target function as external. The test environment should link
   against libxml2 which provides the implementation. */
extern int htmlParseContentType(const xmlChar *val, htmlMetaEncodingOffsets *off);

/* Fuzzer entry point required by libFuzzer / LLVMFuzzer framework. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Limit the allocation size to avoid extremely large allocations in fuzzing
       environments. Adjust the ceiling as needed. */
    const size_t MAX_ALLOC = 65536;
    size_t len = Size;
    if (len > MAX_ALLOC) len = MAX_ALLOC;

    /* Allocate a buffer and ensure it is null-terminated, because
       htmlParseContentType expects a C string (const xmlChar *). */
    xmlChar *buf = (xmlChar *)malloc(len + 1);
    if (buf == NULL)
        return 0;

    if (Data != NULL && len > 0)
        memcpy(buf, Data, len);
    buf[len] = 0; /* null-terminate */

    htmlMetaEncodingOffsets off;
    off.start = off.end = off.size = 0;

    /* Call the target function. Use volatile for the return value to reduce
       the chance the call is optimized out entirely. */
    volatile int res = htmlParseContentType((const xmlChar *)buf, &off);

    /* Touch fields of 'off' and the result to prevent compilers from
       optimizing away the call or its observable effects. */
    if (res) {
        if (off.start > off.end) {
            /* no-op to reference values */
            (void)off.start;
            (void)off.end;
        }
    } else {
        (void)off.size;
    }

    free(buf);
    return 0;
}
