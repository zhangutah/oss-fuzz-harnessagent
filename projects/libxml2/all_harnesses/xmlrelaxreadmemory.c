#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/*
 * Include libxml2 public headers so we can create a valid
 * xmlRelaxNGParserCtxtPtr and manage returned xmlDoc.
 */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>
#include <libxml/xmlerror.h>

/*
 * To reach the static symbol xmlRelaxReadMemory (defined static in
 * relaxng.c), include the implementation file directly so the function
 * is compiled into this translation unit. This allows calling the
 * static function for fuzzing.
 *
 * Note: Depending on build environment, the absolute path below may
 * need to be adjusted. The path used here matches the repository layout
 * used when locating the symbol.
 */
#include "/src/libxml2/relaxng.c"

/*
 * The fuzzer entry point. Constructs a minimal valid xmlRelaxNGParserCtxt,
 * calls xmlRelaxReadMemory with the fuzz input as the XML document buffer,
 * then frees resources.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser globals (safe to call multiple times). */
    xmlInitParser();
    /* Relax-NG types/init if present */
    xmlRelaxNGInitTypes();

    /* Clamp size to int range expected by xmlRelaxReadMemory */
    int intSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a parser context using the fuzz input as the schema buffer.
     * xmlRelaxNGNewMemParserCtxt requires buffer != NULL and size > 0.
     * Using the fuzz bytes ensures the context is non-NULL and ties the
     * fuzzer input to the parser context state (increasing coverage).
     */
    xmlRelaxNGParserCtxtPtr rctxt = NULL;
    if (intSize > 0) {
        rctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, intSize);
    }

    /* If that failed for any reason, try a simple non-NULL URL-based context
     * as a fallback so we still can exercise xmlRelaxReadMemory with fuzz data.
     */
    if (rctxt == NULL) {
        rctxt = xmlRelaxNGNewParserCtxt("fuzz://dummy");
    }

    if (rctxt == NULL) {
        /* If we cannot obtain a parser context, nothing we can do. */
        return 0;
    }

    /*
     * Call the target function under test.
     * xmlRelaxReadMemory is defined static in relaxng.c but is available
     * here because relaxng.c was #included above.
     */
    xmlDocPtr doc = xmlRelaxReadMemory(rctxt, (const char *)Data, intSize);

    /* Free returned document if any */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Free the parser context */
    xmlRelaxNGFreeParserCtxt(rctxt);

    /* Do not call xmlCleanupParser(); fuzzers generally expect long-lived process. */

    return 0;
}
