#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>   /* xmlInitParser, xmlCleanupParser */
#include <libxml/xmlIO.h>    /* xmlOutputBuffer, xmlOutputBufferCreateIO, xmlOutputBufferWrite, xmlOutputBufferFlush, xmlOutputBufferClose */
#include <libxml/encoding.h> /* xmlGetCharEncodingHandler, xmlCharEncodingHandler */

/*
 Fuzzer entry point:
 extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/* volatile sink to make sure we actually use the fuzzer bytes in the callbacks */
static volatile int fuzz_sink = 0;

/* Simple write callback: consume buffer bytes into fuzz_sink and return len.
   If len < 0 return -1 to signal error (not expected here). */
static int
fuzz_write_cb(void *context, const char *buffer, int len) {
    (void)context;
    if (len < 0) return -1;
    /* Touch some bytes so the fuzzer data is used and influences coverage. */
    int acc = 0;
    int limit = len < 64 ? len : 64; /* don't walk huge buffers */
    for (int i = 0; i < limit; i++) {
        acc = (acc * 31) + (unsigned char)buffer[i];
    }
    /* store to volatile to avoid optimization out */
    fuzz_sink ^= acc;
    /* Return number of bytes written. */
    return len;
}

/* Simple close callback: no-op but also use sink to include it in coverage. */
static int
fuzz_close_cb(void *context) {
    (void)context;
    fuzz_sink ^= 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data)
        return 0;

    /* Initialize libxml parser state once (safe to call multiple times). */
    xmlInitParser();

    if (Size == 0)
        return 0;

    /* Use first byte to pick a mode so fuzzer can control behavior:
       mode 0: no encoder, write callback set (default-like)
       mode 1: use UTF-8 encoder, write callback set (exercises conv/encoder path)
       mode 2: use UTF-8 encoder, write callback NULL (exercises buffering w/o immediate write)
    */
    unsigned char mode = Data[0] % 3;

    xmlCharEncodingHandlerPtr encoder = NULL;
    xmlOutputWriteCallback write_cb = fuzz_write_cb;
    xmlOutputCloseCallback close_cb = fuzz_close_cb;

    if (mode == 1 || mode == 2) {
        /* Request a known encoding handler (UTF-8) so encoder != NULL reliably. */
        encoder = xmlGetCharEncodingHandler(XML_CHAR_ENCODING_UTF8);
    }
    if (mode == 2) {
        /* no write callback: set to NULL to exercise the branch where writecallback is absent */
        write_cb = NULL;
        /* keep close callback NULL as well to match absence of write callback (close callback only used if provided) */
        close_cb = NULL;
    }

    /* Create an output buffer that uses our callbacks and possibly an encoder. */
    xmlOutputBufferPtr out = xmlOutputBufferCreateIO(write_cb, close_cb, NULL, encoder);
    if (out == NULL)
        return 0;

    /* Write the remainder of the fuzzer input into the xmlOutputBuffer's internal buffer.
       xmlOutputBufferWrite takes an int length, so cap to INT_MAX.
       Use Data+1 as payload so Data[0] is preserved for mode selection. */
    if (Size > 1) {
        const uint8_t *payload = Data + 1;
        size_t payload_size = Size - 1;
        int to_write = (payload_size > (size_t)INT_MAX) ? INT_MAX : (int)payload_size;
        /* xmlOutputBufferWrite returns -1 on error but we ignore it here. */
        (void)xmlOutputBufferWrite(out, to_write, (const char *)payload);
    } else {
        /* If there's no payload, still try flushing to exercise code paths with empty buffer. */
    }

    /* Call the target function under test. */
    (void)xmlOutputBufferFlush(out);

    /* Close and free the output buffer. */
    (void)xmlOutputBufferClose(out);

    /* Note: Do not call xmlCleanupParser() here per-fuzz-input as it may
       be expensive or interfere with multi-threaded fuzzers. */

    return 0;
}
