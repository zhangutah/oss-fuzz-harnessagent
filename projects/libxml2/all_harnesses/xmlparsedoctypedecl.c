// Fixed fuzzing harness for xmlParseDocTypeDecl
// Builds on the original harness but ensures the parser context always
// starts at a safe "<!DOCTYPE " prefix so xmlParseDocTypeDecl's SKIP(9)
// cannot read past the buffer and cause a heap-buffer-overflow.

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

/* Include the internal parser header (absolute path suggested by project). */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point expected by libFuzzer / LLVMFuzzer. */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Prefix that xmlParseDocTypeDecl expects to have been detected.
       We include a trailing space so SKIP(9) leaves the next char as a blank. */
    const char prefix[] = "<!DOCTYPE ";
    const size_t prefix_len = sizeof(prefix) - 1; /* exclude terminating NUL */

    /* Compute combined size, capping to INT_MAX to be safe for xmlCreateMemoryParserCtxt. */
    size_t combined_size = prefix_len + Size;
    if (combined_size > (size_t)INT_MAX) {
        combined_size = (size_t)INT_MAX;
    }

    /* Allocate buffer and compose the input: prefix + (possibly truncated) Data */
    char *buf = (char *)malloc(combined_size);
    if (buf == NULL) return 0;

    size_t data_to_copy = combined_size - prefix_len; /* may be < Size when capped */
    memcpy(buf, prefix, prefix_len);
    memcpy(buf + prefix_len, Data, data_to_copy);

    /* Initialize libxml2 parser global state. Safe to call multiple times. */
    xmlInitParser();

    /* Create a parser context over our prepared buffer.
       Note: xmlCreateMemoryParserCtxt does not take ownership of the buffer,
       so buf must remain valid until xmlFreeParserCtxt is called. */
    int ctxt_size = (int)combined_size;
    xmlParserCtxt *ctxt = xmlCreateMemoryParserCtxt((const char *)buf, ctxt_size);
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /*
     * Now the parser context's current position begins with "<!DOCTYPE ",
     * so calling xmlParseDocTypeDecl(ctxt) is safe with respect to the SKIP(9)
     * at the start of that function.
     */
    xmlParseDocTypeDecl(ctxt);

    /* Free the parser context and associated resources. */
    xmlFreeParserCtxt(ctxt);

    /* Buffer can now be freed safely. */
    free(buf);

    /* Do not call xmlCleanupParser() here: it would tear down global state used across runs. */
    return 0;
}
