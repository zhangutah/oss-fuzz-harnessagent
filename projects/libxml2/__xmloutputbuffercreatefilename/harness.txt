#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include the header that declares __xmlOutputBufferCreateFilename and
 * xmlOutputBufferClose. Using the absolute path found in the project.
 * Also include parser.h for xmlCleanupParser declaration.
 */
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point expected by libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Reject excessively large inputs to avoid huge allocations in the fuzzer itself. */
    const size_t MAX_FUZZ_INPUT_SIZE = 1024 * 1024; /* 1 MB */
    if (Data == NULL || Size == 0 || Size > MAX_FUZZ_INPUT_SIZE)
        return 0;

    /* Create a NUL-terminated URI string from the fuzz data. */
    char *uri = (char *)malloc(Size + 1);
    if (uri == NULL)
        return 0;
    memcpy(uri, Data, Size);
    uri[Size] = '\0';

    /* Derive a compression value from the last byte of the input (or 0 if none). */
    int compression = 0;
    if (Size > 0)
        compression = (int)(Data[Size - 1] % 16); /* keep it small */

    /* Use a NULL encoder pointer (most callers do this); fuzzing the URI is the main target. */
    xmlCharEncodingHandler *encoder = NULL;

    /* Call the target function. It will internally call xmlInitParser(). */
    xmlOutputBuffer *out = __xmlOutputBufferCreateFilename(uri, encoder, compression);

    /* If an output buffer was returned, close it to release resources. */
    if (out != NULL) {
        /* xmlOutputBufferClose is the documented way to free the buffer. */
        xmlOutputBufferClose(out);
    }

    /* Free the temporary URI buffer. */
    free(uri);

    /* Optionally cleanup parser state for this invocation.
     * Note: libxml2 recommends xmlCleanupParser at the end of the process,
     * but calling it here reduces retained state between fuzz iterations.
     */
    xmlCleanupParser();

    return 0;
}