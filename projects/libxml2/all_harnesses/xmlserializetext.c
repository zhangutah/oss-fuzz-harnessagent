// Fuzzer harness for xmlSerializeText with input-size cap to avoid OOM
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/xmlversion.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>

// If the XML_ESCAPE_* macros are not visible via headers, define them here.
// Values match the ones used in libxml2 private/io.h
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

// xmlSerializeText is not part of the public stable API in many installs,
// so declare it here if it's not provided by the included headers.
#ifdef __cplusplus
extern "C" {
#endif
void xmlSerializeText(xmlOutputBuffer * buf, const xmlChar * string, size_t maxSize, unsigned flags);
#ifdef __cplusplus
}
#endif

// LLVM libFuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimal sanity checks
    if (Data == NULL || Size == 0) {
        return 0;
    }

    // Cap the amount of input we pass to the target to avoid unbounded memory growth.
    // Large fuzzer inputs can cause xmlSerializeText to produce very large outputs
    // (e.g., due to escaping), which in turn grows the xmlBuffer until OOM.
    const size_t MAX_FUZZ_INPUT = 4096; // reasonable cap for fuzzing this routine
    const size_t UTF8_PAD = 4; // allow xmlGetUTF8Char to read up to 4 bytes safely

    size_t inSize = Size;
    if (inSize > MAX_FUZZ_INPUT) inSize = MAX_FUZZ_INPUT;

    // Create an xmlBuffer to collect output (this will be used as the context
    // for the xmlOutputBuffer created below). We must free it on all paths
    // to avoid leaking memory across fuzzing iterations.
    xmlBufferPtr buf = xmlBufferCreate();
    if (buf == NULL) {
        return 0;
    }

    // Create an xmlOutputBuffer that writes into the xmlBuffer
    xmlOutputBufferPtr out = xmlOutputBufferCreateBuffer(buf, NULL);
    if (out == NULL) {
        xmlBufferFree(buf);
        return 0;
    }

    uint8_t *work = (uint8_t *)malloc(inSize + UTF8_PAD);
    if (work == NULL) {
        // out is allocated and must be closed; buf is the context and must be freed.
        xmlOutputBufferClose(out); // flushes and frees the xmlOutputBuffer
        xmlBufferFree(buf);        // free the xmlBuffer we created as context
        return 0;
    }

    memcpy(work, Data, inSize);
    memset(work + inSize, 0, UTF8_PAD);

    // Derive flags from first byte, mapping bits into the available escape flags.
    unsigned flags = 0;
    uint8_t b = Data[0];
    if (b & 0x01) flags |= XML_ESCAPE_ATTR;
    if (b & 0x02) flags |= XML_ESCAPE_NON_ASCII;
    if (b & 0x04) flags |= XML_ESCAPE_HTML;
    if (b & 0x08) flags |= XML_ESCAPE_QUOT;

    // Call the target function. Cast work to xmlChar* (typedef unsigned char).
    xmlSerializeText(out, (const xmlChar *)work, (size_t)inSize, flags);

    // Ensure any buffered data is flushed.
    xmlOutputBufferFlush(out);

    // Clean up
    free(work);
    xmlOutputBufferClose(out); // closes and frees the xmlOutputBuffer
    xmlBufferFree(buf);        // free the xmlBuffer used as context

    return 0;
}
