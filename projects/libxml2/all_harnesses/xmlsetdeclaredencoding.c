#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * Public libxml2 API
 */
#ifdef __cplusplus
extern "C" {
#endif
#include <libxml/parser.h>
#ifdef __cplusplus
}
#endif

/*
 * The private header expects certain macros (XML_HIDDEN, LIBXML_ATTR_FORMAT,
 * and XML_INLINE) to be defined. Define them as minimal/no-op fallbacks so the
 * header can be included in this harness build.
 *
 * Use the absolute path discovered in the codebase so the test driver
 * can access internal structures required to exercise xmlSetDeclaredEncoding.
 */
#ifndef XML_HIDDEN
#define XML_HIDDEN
#endif

#ifndef LIBXML_ATTR_FORMAT
#define LIBXML_ATTR_FORMAT(a,b)
#endif

/* Define XML_INLINE so parser.h which uses 'XML_INLINE' compiles. */
#ifndef XML_INLINE
#define XML_INLINE inline
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "/src/libxml2/include/private/parser.h"
#ifdef __cplusplus
}
#endif

/*
 * Fuzzer entry point.
 *
 * This driver constructs a minimal parser context and input, builds a
 * null-terminated encoding string from the fuzzer bytes (taking ownership
 * of the buffer when calling xmlSetDeclaredEncoding) and calls
 * xmlSetDeclaredEncoding(ctxt, encoding).
 *
 * The function may consume (xmlFree) the encoding or store it in the
 * context; xmlFreeParserCtxt() is called to clean up.
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Initialize libxml internals (safe to call multiple times). */
    xmlInitParser();

    /* Create a new parser context. */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        goto cleanup_and_return;

    /*
     * Prevent the parser from creating encoding handlers / switching input
     * encodings during the test. This avoids entering the heavy/path that may
     * allocate large buffers inside libxml2 in response to fuzzed inputs.
     *
     * Setting XML_PARSE_IGNORE_ENC makes xmlSetDeclaredEncoding skip creating
     * a char-encoding handler and calling xmlInputSetEncodingHandler.
     */
    ctxt->options |= XML_PARSE_IGNORE_ENC;

    /*
     * Prevent the fuzzer from forcing huge allocations inside libxml2 by capping
     * the size passed to xmlCtxtNewInputFromMemory. The fuzzer can supply an
     * arbitrarily large Size, which would make libxml2 attempt to allocate a
     * very large buffer (xmlBufCreateMem) and lead to OOM. Limit to a safe cap.
     */
    const size_t MAX_INPUT_SIZE = 4096; /* reasonable cap for input buffer */
    size_t input_size = Size;
    if (input_size > MAX_INPUT_SIZE)
        input_size = MAX_INPUT_SIZE;

    /*
     * Create a parser input from the provided memory so ctxt->input can be set.
     * xmlCtxtNewInputFromMemory returns a new xmlParserInput or NULL.
     *
     * This is an internal helper (declared in the included private header).
     */
    xmlParserInputPtr input = xmlCtxtNewInputFromMemory(ctxt, /*url*/ NULL,
                                                       (const void *)Data,
                                                       input_size,
                                                       /*encoding*/ NULL,
                                                       /*flags*/ 0);
    if (input == NULL) {
        /* Free context and return if input creation failed. */
        xmlFreeParserCtxt(ctxt);
        goto cleanup_and_return;
    }

    /* Attach the input to the context so xmlSetDeclaredEncoding can act on it.
     * Use xmlCtxtPushInput so the input is placed on ctxt->inputTab and will
     * be freed by xmlFreeParserCtxt. */
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        /* Push failed: free the input we created and the context. */
        xmlFreeInputStream(input);
        xmlFreeParserCtxt(ctxt);
        goto cleanup_and_return;
    }

    /*
     * To exercise multiple branches in xmlSetDeclaredEncoding, toggle the
     * input flags based on the first byte (if present). This is not strictly
     * necessary, but helps the fuzzer reach more code paths.
     *
     * Note: We keep XML_PARSE_IGNORE_ENC set on ctxt->options above which
     * prevents xmlSetDeclaredEncoding from creating encoding handlers which
     * could trigger large allocations.
     */
    if (Size > 0 && (Data[0] & 1)) {
        /* set an AUTO_ENCODING hint (use UTF-8 auto-detect) */
#ifdef XML_INPUT_AUTO_UTF8
        ctxt->input->flags |= XML_INPUT_AUTO_UTF8;
#else
        /* If the specific symbol is not available, set a generic AUTO bit. */
        ctxt->input->flags |= XML_INPUT_AUTO_ENCODING;
#endif
    } else {
        /* Ensure there is no pre-declared encoding flag so the primary branch runs. */
        ctxt->input->flags &= ~XML_INPUT_HAS_ENCODING;
    }

    /*
     * Prepare a null-terminated encoding string that xmlSetDeclaredEncoding
     * will take ownership of. The function expects a C string (xmlChar*),
     * so ensure we add a trailing NUL.
     *
     * Cap the encoding string length to avoid allocating enormous buffers
     * controlled by the fuzzer.
     */
    const size_t MAX_ENCODING_LEN = 256;
    size_t enc_len = Size;
    if (enc_len > MAX_ENCODING_LEN)
        enc_len = MAX_ENCODING_LEN;

    xmlChar *encoding = (xmlChar *)malloc(enc_len + 1);
    if (encoding == NULL) {
        xmlFreeParserCtxt(ctxt);
        goto cleanup_and_return;
    }
    if (enc_len > 0)
        memcpy(encoding, Data, enc_len);
    encoding[enc_len] = '\0';

    /* Call the function under test. It takes ownership of 'encoding'. */
    xmlSetDeclaredEncoding(ctxt, encoding);
    /* Do NOT free 'encoding' here; ownership transferred to xmlSetDeclaredEncoding/ctxt. */

    /* Clean up parser context (this will free retained encoding if stored). */
    xmlFreeParserCtxt(ctxt);

cleanup_and_return:
    /* Optional: clean up global parser state. */
    xmlCleanupParser();

    return 0;
}
