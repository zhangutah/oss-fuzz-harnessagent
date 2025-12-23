// Fixed fuzz driver for xmlParserInputBufferGrow.
// Ensures fuzz data actually affects behavior by making the read callback
// vary its return values (including error and EOF) based on input bytes.
//
// This file is intended to replace the original harness. It keeps the same
// LLVMFuzzerTestOneInput signature.

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <libxml/xmlIO.h>
#include <libxml/parser.h>
#include <libxml/encoding.h>
#ifdef __cplusplus
}
#endif

/*
 * Fuzz driver for:
 *   int xmlParserInputBufferGrow(xmlParserInputBuffer * in, int len);
 *
 * Strategy changes (to improve effectiveness):
 * - Make the read callback use the fuzz bytes not only as data to copy,
 *   but also as control bytes to signal EOF or error or to limit read sizes.
 *   This ensures different code paths in xmlParserInputBufferGrow are exercised.
 * - Keep xmlInitParser() call to initialize libxml internals.
 */

typedef struct {
   const uint8_t *data;
   size_t size;
   size_t pos;
} FuzzReadCtx;

/* xmlInputReadCallback: returns number of bytes read, 0 for EOF, -1 for error. */
/* Use the input bytes both as payload and as control flags to vary behavior. */
static int
fuzz_read_callback(void *context, char *buffer, int len) {
    if (context == NULL || buffer == NULL || len <= 0)
        return 0;

    FuzzReadCtx *ctx = (FuzzReadCtx *)context;
    if (ctx->pos >= ctx->size)
        return 0; /* EOF */

    size_t avail = ctx->size - ctx->pos;

    /* Peek a control byte to vary behavior, but don't go past available data. */
    uint8_t control = ctx->data[ctx->pos];

    /* Special control values:
       - 0xFF => simulate I/O error (return -1) and consume one byte
       - 0x00 => simulate EOF (return 0) and consume one byte
       Otherwise: limit the number of bytes returned using control to vary chunk sizes.
    */
    if (control == 0xFF) {
        /* consume control byte to make progress and then return error */
        ctx->pos++;
        return -1;
    }
    if (control == 0x00) {
        ctx->pos++;
        return 0;
    }

    /* Determine how many bytes to copy, influenced by control byte to vary behavior. */
    size_t toCopy = (size_t)len;
    if (toCopy > avail)
        toCopy = avail;

    /* Limit the max bytes read using control (1..64), ensuring variety. */
    size_t controlLimit = (size_t)(control % 64) + 1;
    if (toCopy > controlLimit)
        toCopy = controlLimit;

    /* Copy available payload into buffer. */
    memcpy(buffer, ctx->data + ctx->pos, toCopy);
    ctx->pos += toCopy;

    /* Return number of bytes read (fits in int because toCopy <= (size_t)len). */
    return (int)toCopy;
}

/* Ensure libxml is initialized once. */
static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        /* Suppress libxml's generic error output (optional) */
        xmlSetGenericErrorFunc(NULL, NULL);
        initialized = 1;
    }
}

/* Fuzzer entry point with the exact signature requested */
#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ensure_libxml_initialized();

    /* Prepare read context referencing the fuzzer input (valid for duration of this call). */
    FuzzReadCtx ctx;
    ctx.data = Data;
    ctx.size = Size;
    ctx.pos = 0;

    /* Use UTF-8 encoding and create the parser input buffer via CreateIO so the callbacks are set properly. */
    xmlParserInputBuffer *in = xmlParserInputBufferCreateIO((xmlInputReadCallback)fuzz_read_callback, NULL, &ctx, XML_CHAR_ENCODING_UTF8);
    if (in == NULL) {
        return 0;
    }

    if (Data == NULL || Size == 0) {
        /* Still exercise function with no data: call once and cleanup. */
        (void)xmlParserInputBufferGrow(in, 0);
        xmlFreeParserInputBuffer(in);
        return 0;
    }

    /* Call xmlParserInputBufferGrow with several lengths derived from the input:
       - a small len derived from the first byte (guaranteed >= 1)
       - the full input size (capped to INT_MAX)
       - -1 (edge case)
       Then loop with a modest length to consume the rest of the input.
    */
    int len_small = (int)(Data[0] % 4095) + 1; /* ensure >= 1 to avoid immediate EOF */
    if (len_small < 1) len_small = 1;

    /* First call: small len */
    (void)xmlParserInputBufferGrow(in, len_small);

    /* Second call: use the full Size (capped to INT_MAX) */
    int len_full = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    (void)xmlParserInputBufferGrow(in, len_full);

    /* Third call: negative len to trigger handling (the function will clamp to MINLEN) */
    (void)xmlParserInputBufferGrow(in, -1);

    /* Consume remaining data to ensure the fuzzer bytes are actually used.
       Use a modest buffer request repeatedly until EOF or error. */
    for (;;) {
        int r = xmlParserInputBufferGrow(in, 1024);
        if (r <= 0) break;
        /* continue consuming */
    }

    /* Clean up */
    xmlFreeParserInputBuffer(in);

    return 0;
}