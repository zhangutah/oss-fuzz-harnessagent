#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

/* Project headers (absolute paths discovered from repository) */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/encoding.h"
#include "/src/libxml2/include/libxml/xmlerror.h"

/* Suppress libxml2 error output from stderr */
static void xml_noop_error(void *ctx, const char *msg, ...) {
    (void)ctx;
    (void)msg;
}

/* Ensure libxml is initialized once (simple thread-unsafe guard is sufficient for many fuzzers) */
static int libxml_inited = 0;
static void ensure_libxml_init(void) {
    if (!libxml_inited) {
        xmlInitParser();
        /* Redirect generic errors to noop to avoid noisy logs during fuzzing */
        xmlSetGenericErrorFunc(NULL, xml_noop_error);
        libxml_inited = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) {
        return 0;
    }

    ensure_libxml_init();

    /* xmlParserInputBufferCreateStatic takes an int length; cap to INT_MAX */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a static input buffer from the fuzzer data.
       Use XML_CHAR_ENCODING_NONE to let the parser auto-detect or treat bytes as-is. */
    xmlParserInputBufferPtr input = xmlParserInputBufferCreateStatic((const char *)Data, len, XML_CHAR_ENCODING_NONE);
    if (input == NULL) {
        return 0;
    }

    /* Call the target function. Pass a NULL SAX handler to use defaults.
       Note: xmlIOParseDTD takes ownership / manages the input buffer (it will free/manages it),
       so do NOT free 'input' after calling xmlIOParseDTD. */
    xmlDtdPtr dtd = xmlIOParseDTD(NULL, input, XML_CHAR_ENCODING_NONE);

    if (dtd != NULL) {
        /* Free the DTD; the library will manage any other associated resources.
           Do NOT call xmlFreeParserInputBuffer(input) here since ownership was transferred. */
        xmlFreeDtd(dtd);
    } else {
        /* Do not free 'input' here: xmlIOParseDTD may already have freed it / taken care of it. */
    }

    /* Do not call xmlCleanupParser() here: that is global and usually done at process end. */
    return 0;
}
