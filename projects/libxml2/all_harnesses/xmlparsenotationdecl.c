#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h> /* for memset */

/* Include project headers (absolute paths from the source tree) */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Fuzzer entry point for xmlParseNotationDecl.
 *
 * The fuzzer provides an in-memory buffer (Data, Size). We create a
 * parser context from a safe-sized prefix of that buffer and call
 * xmlParseNotationDecl on it.
 *
 * Note: xmlCreateMemoryParserCtxt (and functions it calls) may allocate
 * memory proportional to the size argument. To avoid out-of-memory
 * conditions when the fuzzer provides extremely large inputs, we cap
 * the size passed to the parser to MAX_INPUT_BYTES.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Limit the input passed to libxml2 to avoid huge internal allocations */
    const size_t MAX_INPUT_BYTES = 64 * 1024; /* 64 KiB */
    size_t use_size = (Size > MAX_INPUT_BYTES) ? MAX_INPUT_BYTES : Size;

    /* xmlCreateMemoryParserCtxt takes an int size; guard against overflow and cap */
    int intSize = (use_size > (size_t)INT_MAX) ? INT_MAX : (int)use_size;
    if (intSize <= 0) return 0;

    /* Create a parser context from the raw input buffer (only the prefix) */
    xmlParserCtxt *ctxt = xmlCreateMemoryParserCtxt((const char *)Data, intSize);
    if (ctxt == NULL) return 0;

    /*
     * To avoid triggering any user callbacks (SAX) that might be
     * uninitialized or cause external effects, clear the sax handler
     * callbacks if present BUT keep the pointer so xmlFreeParserCtxt can
     * correctly free the allocated handler and avoid leaks.
     */
    if (ctxt->sax != NULL) {
        memset(ctxt->sax, 0, sizeof(xmlSAXHandler));
    }

    /* Call the target function under test */
    xmlParseNotationDecl(ctxt);

    /* Clean up the parser context */
    xmlFreeParserCtxt(ctxt);

    return 0;
}
