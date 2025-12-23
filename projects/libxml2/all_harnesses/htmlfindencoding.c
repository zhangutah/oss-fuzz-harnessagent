#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * This fuzz driver calls the internal htmlFindEncoding function from
 * libxml2's HTMLparser.c. To access the (static) function directly we
 * include the C file for that translation unit so the function is
 * available in this compilation unit.
 *
 * NOTE: The absolute path used below (/src/libxml2/HTMLparser.c) matches the
 * location reported in the workspace. Adjust the include path if you place
 * this driver in a different build environment.
 */
#include "/src/libxml2/HTMLparser.c"

/* Fuzzer entrypoint. */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Limit allocation size to avoid extremely large allocations during fuzzing */
    const size_t MAX_FUZZ_INPUT = 1 << 20; /* 1MB */
    if (Size > MAX_FUZZ_INPUT)
        Size = MAX_FUZZ_INPUT;

    /* Allocate buffer and ensure it's NUL-terminated as expected by htmlFindEncoding */
    unsigned char *buffer = (unsigned char *)malloc(Size + 1);
    if (buffer == NULL)
        return 0;
    if (Size > 0 && Data != NULL)
        memcpy(buffer, Data, Size);
    buffer[Size] = 0;

    /* Allocate a minimal parser context and its input structure.
     * The structures xmlParserCtxt and xmlParserInput are defined in
     * parserInternals.h which is included by HTMLparser.c that we pulled in.
     *
     * We only initialize the fields that htmlFindEncoding reads:
     *   - ctxt->input
     *   - ctxt->input->flags
     *   - ctxt->input->cur
     *   - ctxt->input->end
     *
     * All other fields can remain zeroed.
     */
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr)calloc(1, sizeof(xmlParserCtxt));
    if (ctxt == NULL) {
        free(buffer);
        return 0;
    }

    xmlParserInputPtr in = (xmlParserInputPtr)calloc(1, sizeof(xmlParserInput));
    if (in == NULL) {
        free(ctxt);
        free(buffer);
        return 0;
    }

    /* Set up the input buffer pointers. htmlFindEncoding expects:
     *   - input->cur pointing to the start of data
     *   - input->end pointing to the position of the NUL terminator
     *   - the NUL terminator to actually be present at *end
     * Also, if XML_INPUT_HAS_ENCODING is set in input->flags the function
     * returns NULL early, so ensure flags are cleared.
     */
    in->cur = (const xmlChar *)buffer;
    in->end = (const xmlChar *)(buffer + Size); /* points to NUL */
    in->flags = 0;

    ctxt->input = in;

    /* Call the target function. Because HTMLparser.c was included above,
     * htmlFindEncoding is available in this TU even though it's declared static.
     */
    xmlChar *enc = htmlFindEncoding(ctxt);

    /* Free memory returned by htmlFindEncoding if any. Use xmlFree if available
     * (part of libxml2 allocation API); fall back to free otherwise.
     */
#ifdef HAVE_LIBXML_XMLFREE /* just in case a build system defines this */
    if (enc) xmlFree(enc);
#else
    if (enc) free(enc);
#endif

    /* Clean up our temporary structures and buffer. Note: xmlFree/xmlMalloc are
     * used by libxml2 functions; since we didn't use them to allocate ctxt/input
     * we free with standard free().
     */
    free(in);
    free(ctxt);
    free(buffer);

    return 0;
}
