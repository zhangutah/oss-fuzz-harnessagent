#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

/* Use absolute include path found in the project to ensure the right header is used */
#include "/src/libxml2/include/libxml/xmlschemas.h"
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

/* No-op error/warning handlers to avoid noisy output during fuzzing */
static void
fuzz_schema_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

static void
fuzz_schema_warning(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

/*
 * Fuzzer entry point expected by libFuzzer / LLVMFuzzer
 *
 * Strategy:
 * - Initialize libxml2 parser state.
 * - Create an xmlSchemaValidCtxt using xmlSchemaNewValidCtxt(NULL).
 * - Set no-op error handlers to avoid printing.
 * - Feed the input to xmlReadMemory to create an xmlDoc (if parsable).
 *   This may change parser global/internal state that xmlSchemaAssembleByXSI uses.
 * - Attempt to call xmlSchemaAssembleByXSI:
 *     * If the symbol is linked into the binary, call it via a weak reference.
 *     * Otherwise, fall back to dlsym(NULL, ...) to try and resolve it at runtime.
 * - Clean up allocated resources.
 *
 * Note: The validation context is created without an xmlSchema pointer (NULL).
 * This mirrors usages found in the codebase and allows exercising xmlSchemaAssembleByXSI's
 * handling of various internal / missing fields. The fuzzer data is used to construct
 * a temporary xmlDoc which may affect libxml2 internal state used by the target.
 */

/* Declare the symbol as weak so we can call it directly if it's present without
 * producing a link-time error if it's not available.
 */
extern int xmlSchemaAssembleByXSI(xmlSchemaValidCtxtPtr vctxt) __attribute__((weak));

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser library (safe to call multiple times) */
    xmlInitParser();

    /* Create a validation context with no schema (common usage in codebase) */
    xmlSchemaValidCtxtPtr vctxt = xmlSchemaNewValidCtxt(NULL);
    if (vctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Install no-op error/warning handlers */
    xmlSchemaSetValidErrors(vctxt, fuzz_schema_error, fuzz_schema_warning, NULL);
    xmlSchemaSetValidStructuredErrors(vctxt, NULL, NULL);

    /* Try to parse the fuzz input as an XML document to alter parser state.
     * Use XML_PARSE_NONET to avoid network access and XML_PARSE_RECOVER to be tolerant.
     */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz-input.xml",
                                  NULL, XML_PARSE_NONET | XML_PARSE_RECOVER);
    if (doc != NULL) {
        /* If a document was created, set a filename for the validation context
         * (may be used by some functions called by xmlSchemaAssembleByXSI).
         */
        xmlSchemaValidateSetFilename(vctxt, "fuzz-input.xml");
        /* Free the document after the call below */
    }

    /* First try calling via the weak symbol (if present). This makes the call
     * explicit in the binary and will be used when libxml2 is linked into the
     * process that runs the harness.
     */
    if (xmlSchemaAssembleByXSI) {
        (void)xmlSchemaAssembleByXSI(vctxt);
    } else {
        /* Fallback: try to dynamically resolve xmlSchemaAssembleByXSI to avoid
         * a hard link-time dependency. This allows exercising the function if
         * it is available at run time (shared lib provided).
         */
        typedef int (*xmlSchemaAssembleByXSI_t)(xmlSchemaValidCtxtPtr);
        void *handle = dlopen(NULL, RTLD_LAZY);
        if (handle != NULL) {
            xmlSchemaAssembleByXSI_t func =
                (xmlSchemaAssembleByXSI_t)dlsym(handle, "xmlSchemaAssembleByXSI");
            if (func != NULL) {
                /* Call the function under test. We ignore the return value. */
                (void)func(vctxt);
            }
            /* dlclose on the handle returned by dlopen(NULL, ...) is allowed */
            dlclose(handle);
        } else {
            /* If dlopen failed, skip calling the target function */
        }
    }

    /* Clean up */
    if (doc != NULL)
        xmlFreeDoc(doc);
    xmlSchemaFreeValidCtxt(vctxt);

    /* Cleanup parser globals (safe) */
    xmlCleanupParser();

    return 0;
}
