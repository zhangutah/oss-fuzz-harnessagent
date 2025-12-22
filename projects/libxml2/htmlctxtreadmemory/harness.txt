#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>

#include <libxml/HTMLparser.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/* libxml2 initialization once per process. */
static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (!initialized) {
        /* xmlInitParser is safe to call multiple times; ensure it's done once. */
        xmlInitParser();
        initialized = 1;
    }
}

/* A minimal no-op structured error handler to avoid noisy stderr output
   (optional). Signature uses libxml2 types. */
static void noopStructuredError(void *userData, xmlErrorPtr error) {
    (void)userData;
    (void)error;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    ensure_libxml_initialized();

    /* Create a parser context */
    xmlParserCtxt *ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        return 0;
    }

    /* (Removed xmlCtxtSetStructuredErrorFunc call because it may not be
       available in some libxml2 builds and caused an undefined reference.) */

    /* Prepare buffer and handle zero-size or very large inputs. */
    const char *buf_ptr = NULL;
    char dummy = 0;
    if (Size == 0) {
        buf_ptr = &dummy;
    } else {
        buf_ptr = (const char *)Data;
    }

    /* htmlCtxtReadMemory takes an int size parameter. Clamp to INT_MAX. */
    int size_param = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Call the target function. Use NULL for URL and encoding and 0 for options. */
    xmlDocPtr doc = htmlCtxtReadMemory(ctxt, buf_ptr, size_param, NULL, NULL, 0);

    /* Free the produced document if any. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Free the parser context. */
    xmlFreeParserCtxt(ctxt);

    /* Note: We intentionally do not call xmlCleanupParser() here because
       libFuzzer may call this function many times and xmlCleanupParser()
       can tear down global state needed across runs. If you prefer to
       call it at process exit, consider registering an atexit handler. */

    return 0;
}
