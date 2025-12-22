// Fixed harness for fuzzing xmlOutputBufferWrite.
// The original compilation failed because XML_HIDDEN (an internal visibility
// macro defined in libxml.h) was not defined before including private/buf.h.
// Define it as empty if not already defined so private/buf.h can be parsed.
//
// Do not change the harness function signature.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

/* Include libxml2 headers used by xmlOutputBufferWrite and helpers.
   - xmlIO.h declares xmlOutputBuffer and xmlOutputBufferWrite.
   - private/buf.h declares xmlBufCreate / xmlBufFree / xmlBufAdd used internally.
   These are project headers from the libxml2 source tree. */
#include <libxml/xmlIO.h>

/* private/buf.h uses XML_HIDDEN which is normally defined in libxml.h.
   In this fuzzing harness we don't need the visibility attributes, just make
   sure the macro is defined so the header parses cleanly. */
#ifndef XML_HIDDEN
#define XML_HIDDEN
#endif

#include "private/buf.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Allocate and initialize a minimal xmlOutputBuffer structure.
       xmlOutputBufferWrite expects out->buffer (xmlBuf *) to be valid
       when out->writecallback is NULL (we leave writecallback NULL). */
    xmlOutputBuffer *out = (xmlOutputBuffer *)malloc(sizeof(xmlOutputBuffer));
    if (!out) return 0;
    memset(out, 0, sizeof(*out));

    /* Create an xmlBuf to serve as the output buffer.
       Choose a reasonable initial size; if Size is large, cap the initial
       allocation to avoid huge allocations during fuzzing. */
    size_t initial_size = 256;
    if (Size > 0 && Size < 1024) initial_size = Size;
    out->buffer = xmlBufCreate(initial_size);
    if (out->buffer == NULL) {
        free(out);
        return 0;
    }

    /* Ensure other fields are sane */
    out->conv = NULL;
    out->encoder = NULL;
    out->writecallback = NULL;
    out->closecallback = NULL;
    out->context = NULL;
    out->written = 0;
    out->error = 0;

    /* Determine a length to pass to xmlOutputBufferWrite.
       Use the fuzz input size but cap to INT_MAX and avoid negative lengths. */
    int len;
    if (Size > (size_t)INT_MAX) len = INT_MAX;
    else len = (int)Size;

    /* For extra variation, if size is non-zero and the first byte exists,
       use it to decide to pass only a prefix length. This helps exercise
       different code paths while still using the provided data as content. */
    if (Size > 0) {
        /* choose a small length in many cases to avoid excessive internal work */
        unsigned char selector = Data[0];
        if ((selector & 0x3) == 0 && len > 1)
            len = (len > 16) ? 16 : len; /* small bounded write */
        else if ((selector & 0x3) == 1 && len > 512)
            len = 512;
        /* else keep len as-is (up to Size) */
    }

    /* Call the target function. We cast Data to const char* as required by the API. */
    (void)xmlOutputBufferWrite(out, len, (const char *)Data);

    /* Clean up allocated buffers. xmlBufFree is provided in private/buf.h. */
    if (out->conv != NULL)
        xmlBufFree(out->conv);
    if (out->buffer != NULL)
        xmlBufFree(out->buffer);
    free(out);

    return 0;
}