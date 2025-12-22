#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/*
 * Forward declaration of the internal type used by the function signature
 * (kept as in the original harness so types match).
 */
typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

/*
 * Note:
 * xmlRelaxNGParseInterleave is a static (file-local) function in relaxng.c.
 * To ensure the harness actually calls that internal function, include the
 * implementation file so the static function becomes available in this
 * translation unit. This is a common fuzzing technique to exercise
 * file-local symbols.
 */
#include "../relaxng.c"

/*
 * Fuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the libxml2 parser library (safe to call multiple times). */
    xmlInitParser();

    /* Try to create a Relax-NG parser context from the input bytes.
     * If that fails, fall back to a simple named context.
     */
    xmlRelaxNGParserCtxtPtr rng_ctxt = NULL;
#if defined(HAVE_LIBXML_XMLRELAXNG_H) || 1
    /* xmlRelaxNGNewMemParserCtxt is declared in relaxng.h and is useful
     * to initialize a parser context using input bytes. Use it if available.
     */
    rng_ctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
#endif
    if (rng_ctxt == NULL) {
        /* Fallback: create a context with a dummy non-NULL URL to avoid NULL returns. */
        rng_ctxt = xmlRelaxNGNewParserCtxt("fuzz");
    }

    /* Parse the input as an XML document to produce a tree; use safe parse flags. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz-input", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);

    /* Choose a node to pass to xmlRelaxNGParseInterleave.
     * Prefer the document root if parsed, otherwise NULL.
     */
    xmlNodePtr node = NULL;
    if (doc != NULL) {
        node = xmlDocGetRootElement(doc);
    }

    /*
     * Call the target function directly. Including relaxng.c above makes the
     * static xmlRelaxNGParseInterleave function available in this TU.
     */
#ifdef __cplusplus
    /* ensure C linkage if compiled as C++ */
extern "C" {
#endif
    /* The function is static in relaxng.c, but because relaxng.c is included
     * in this file the symbol is visible here. Call it to exercise the code.
     */
    if (rng_ctxt != NULL && node != NULL) {
        (void) xmlRelaxNGParseInterleave(rng_ctxt, node);
    }
#ifdef __cplusplus
}
#endif

    /* Clean up allocated resources to avoid memory growth across runs. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    if (rng_ctxt != NULL) {
        xmlRelaxNGFreeParserCtxt(rng_ctxt);
    }

    /* Optional: cleanup global parser state (can be called at program end). */
    /* xmlCleanupParser(); */
    return 0;
}