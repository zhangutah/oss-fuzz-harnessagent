#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Ensure the HTML-specific code in HTMLtree.c is enabled when the file is included.
#ifndef LIBXML_HTML_ENABLED
#define LIBXML_HTML_ENABLED 1
#endif

// Include the implementation directly so the internal typedef htmlMetaEncoding
// and the function htmlUpdateMetaEncoding are available to this translation unit.
// Use the absolute path discovered in the project.
#include "/src/libxml2/HTMLtree.c"

// libFuzzer entrypoint
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Defensive checks
    if (Data == NULL || Size == 0)
        return 0;

    // Create a NUL-terminated encoding string from the input data.
    // Limit the length to avoid extremely large allocations in pathological cases.
    size_t maxEnc = Size;
    if (maxEnc > 1 << 20) // 1MB cap
        maxEnc = 1 << 20;
    char *encoding = (char *)malloc(maxEnc + 1);
    if (encoding == NULL)
        return 0;
    memcpy(encoding, Data, maxEnc);
    encoding[maxEnc] = '\0';

    // Construct a htmlMetaEncoding instance.
    // The type htmlMetaEncoding is defined inside HTMLtree.c which we included above.
    htmlMetaEncoding menc;
    memset(&menc, 0, sizeof(menc));

    // Initialize offsets in a deterministic but input-influenced way:
    // Use up to the first 3 * sizeof(size_t) bytes (if available) to derive start/end/size.
    size_t offBytesNeeded = 3 * sizeof(size_t);
    size_t offBuf[3] = {0, 0, 0};
    size_t bytesToCopy = (Size < offBytesNeeded) ? Size : offBytesNeeded;
    if (bytesToCopy > 0) {
        // copy available bytes into tmp
        unsigned char tmp[3 * sizeof(size_t)];
        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, Data, bytesToCopy);
        for (size_t i = 0; i < 3; ++i) {
            size_t val = 0;
            // assemble size_t from tmp
            for (size_t b = 0; b < sizeof(size_t); ++b) {
                val |= ((size_t)tmp[i * sizeof(size_t) + b]) << (8 * b);
            }
            offBuf[i] = val;
        }
    }

    // Normalize offsets to reasonable bounds to avoid overflow in called code.
    const size_t SAFE_MAX = (size_t)1024 * 1024; // 1MB
    // Ensure size is at least 1 to avoid division/modulo by zero and to make a valid buffer.
    size_t bufSize = (offBuf[2] % SAFE_MAX) + 1; // in [1, SAFE_MAX]
    // start in [0, bufSize-1]
    size_t start = offBuf[0] % bufSize;
    // end in [start, bufSize]
    size_t end;
    {
        size_t remaining = bufSize - start; // >=1
        // choose an offset in [0, remaining] so end in [start, bufSize]
        end = start + (offBuf[1] % (remaining + 1));
    }

    menc.off.size = bufSize;
    menc.off.start = start;
    menc.off.end = end;

    // Allocate and initialize attrValue so that htmlUpdateMetaEncoding can safely read it.
    // Use xmlMalloc/xmlFree since the codebase uses xmlMalloc for other allocations.
    xmlChar *attrValue = (xmlChar *)xmlMalloc(menc.off.size + 1);
    if (attrValue == NULL) {
        free(encoding);
        return 0;
    }
    // Fill attrValue with input-derived bytes when available, else fill with 'A'.
    size_t headerUsed = bytesToCopy;
    size_t contentAvailable = 0;
    if (Size > headerUsed)
        contentAvailable = Size - headerUsed;
    size_t toCopy = (contentAvailable >= menc.off.size) ? menc.off.size : contentAvailable;
    if (toCopy > 0) {
        memcpy(attrValue, Data + headerUsed, toCopy);
    }
    if (toCopy < menc.off.size) {
        // fill remainder with ASCII 'A' to keep printable content
        memset(attrValue + toCopy, 'A', menc.off.size - toCopy);
    }
    attrValue[menc.off.size] = 0;

    // Set up the htmlMetaEncoding to point to our buffer.
    menc.attr = NULL; // not needed by htmlUpdateMetaEncoding
    menc.attrValue = (const xmlChar *)attrValue;

    // Call the target function. It returns xmlChar* (alias unsigned char *).
    // If non-NULL, free it with xmlFree (provided by the libxml2 code included).
    xmlChar *ret = htmlUpdateMetaEncoding(&menc, encoding);
    if (ret != NULL) {
        xmlFree(ret);
    }

    xmlFree(attrValue);
    free(encoding);
    return 0;
}
