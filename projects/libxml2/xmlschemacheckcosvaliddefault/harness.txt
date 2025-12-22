#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Ensure libxml schema parts are enabled when compiling this TU */
#ifndef LIBXML_SCHEMAS_ENABLED
#define LIBXML_SCHEMAS_ENABLED
#endif

/* Include libxml public headers for types used by the harness */
#include <libxml/parser.h>
#include <libxml/xmlschemas.h>
#include <libxml/schemasInternals.h>

/* Include the implementation so the static function xmlSchemaCheckCOSValidDefault
 * is available in this translation unit. Adjust path if necessary.
 */
#include "/src/libxml2/xmlschemas.c"

/* Forward-declare helper free function if present in the included implementation.
 * If it's static in the implementation, the call will still resolve because
 * the function is in the same translation unit after inclusion.
 */
void xmlSchemaFreeValue(xmlSchemaValPtr val);

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic sanity */
    if (Data == NULL) return 0;

    /* Initialize libxml parser state (no-op in many builds but safe) */
    xmlInitParser();

    /* Create a validation context. Passing NULL for xmlSchema* is fine for
     * constructing a minimal context used by the target function.
     */
    xmlSchemaValidCtxtPtr vctxt = xmlSchemaNewValidCtxt(NULL);
    if (vctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Prepare element info (vctxt->inode) used by xmlSchemaCheckCOSValidDefault.
     * xmlSchemaCheckCOSValidDefault expects vctxt->inode and inode->typeDef
     * to be valid. Use the internal helper to create a fresh element info and
     * assign a built-in simple type for safe validation.
     *
     * xmlSchemaValidatorPushElem is static in xmlschemas.c, but because the
     * .c file is included into this TU, the symbol is available here.
     */
    if (xmlSchemaValidatorPushElem(vctxt) != 0) {
        xmlSchemaFreeValidCtxt(vctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Assign a built-in simple type (string) so the checker has a type to work on.
     * This avoids dereferencing NULL typeDef inside the target function.
     */
    if (vctxt->inode != NULL) {
        vctxt->inode->typeDef = xmlSchemaGetBuiltInType(XML_SCHEMAS_STRING);
    }

    /* Copy fuzzer data into a nul-terminated buffer to present as a value */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        xmlSchemaFreeValidCtxt(vctxt);
        xmlCleanupParser();
        return 0;
    }
    if (Size > 0) memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Prepare holder for returned value (if any) */
    xmlSchemaValPtr val = NULL;

    /* Call the target function under fuzzing */
    /* It expects xmlChar* (which is unsigned char* in libxml); cast accordingly */
    (void)xmlSchemaCheckCOSValidDefault(vctxt, (const xmlChar *)buf, &val);

    /* If a value object was produced, free it if feasible */
    if (val != NULL) {
        /* xmlSchemaFreeValue exists in the implementation; safe to call. */
        xmlSchemaFreeValue(val);
        val = NULL;
    }

    /* Tear down the validation context */
    xmlSchemaFreeValidCtxt(vctxt);

    /* Free temporary buffer and cleanup parser */
    free(buf);
    xmlCleanupParser();

    return 0;
}
