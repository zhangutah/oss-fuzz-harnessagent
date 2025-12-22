/*
 * Fuzzer driver to exercise xmlRelaxNGValidateDefinition
 *
 * This driver is written to be built inside the libxml2 sources tree
 * (e.g. in src/libxml2/fuzz). It re-uses the project's fuzz helpers
 * (declared below) and includes the relaxng implementation so that the
 * static function xmlRelaxNGValidateDefinition is available in this TU.
 *
 * Build note (example):
 *   cc -I.. -I.. -I../include -g -O1 -fsanitize=fuzzer,address -o relaxng_fuzzer \
 *       regexp.c
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * We avoid including "fuzz.h" directly here to prevent a conflicting
 * declaration of LLVMFuzzerTestOneInput (some versions of fuzz.h declare
 * LLVMFuzzerTestOneInput(const char*, size_t) which conflicts with the
 * standard libFuzzer signature below). Instead declare only the fuzz
 * helpers used in this file. The real definitions are provided by the
 * project's fuzz helpers at link time.
 */

/* Prototypes for a small set of fuzz helper functions used by this TU. */
void xmlFuzzMemSetup(void);
void xmlFuzzResetFailure(void);
void xmlFuzzErrorFunc(void *ctx, const char *msg, ...);
void xmlFuzzSErrorFunc(void *ctx, const struct _xmlError *error);

/*
 * Include the implementation so the static function
 * xmlRelaxNGValidateDefinition is available in this TU.
 *
 * The relative path assumes this file is placed in the libxml2/fuzz
 * directory and relaxng.c is in the parent directory.
 *
 * If your build layout is different, adjust the include path as needed,
 * for example: #include "../relaxng.c"
 */
#include "../relaxng.c"

/* Forward declare libxml2 public APIs we use (headers are indirectly included
 * by relaxng.c, but declare again for clarity). */
#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/tree.h>

/* Optional fuzzer initialization */
int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    /* Set up the libxml2 fuzz memory hooks, etc. */
    xmlFuzzMemSetup();

    /* Initialize the library (parser, catalog, ...). */
    xmlInitParser();

    /* Optional: initialize RelaxNG types if needed by the library version. */
#if defined(HAVE_REGEXP_FUZZER) || 1
    /* Some builds may need initialization; it's safe to call. */
    (void) xmlRelaxNGInitTypes();
#endif

    return 0;
}

/* Fuzzer entry point expected by libFuzzer/OSS-Fuzz harnesses.
 *
 * Keep this signature exactly as libFuzzer expects: const uint8_t *Data, size_t Size
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /*
     * Use the input bytes as a Relax-NG schema buffer.
     * Create a parser ctxt and parse it into an xmlRelaxNGPtr.
     * If parsing succeeds we create a validation context and attempt
     * to locate a definition to pass to xmlRelaxNGValidateDefinition.
     *
     * Note: xmlRelaxNGValidateDefinition is defined static in relaxng.c
     * and is available here because relaxng.c was included in this translation unit.
     */

    /* Copy the input to a null-terminated buffer for the parser APIs. */
    char *buf = (char *)malloc(Size + 1);
    if (!buf)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
    if (pctxt == NULL) {
        free(buf);
        return 0;
    }

    /* Parse the schema from the fuzz input buffer */
    xmlRelaxNGPtr schema = xmlRelaxNGParse(pctxt);
    xmlRelaxNGFreeParserCtxt(pctxt);

    if (schema == NULL) {
        free(buf);
        return 0;
    }

    /* Create a validation context for this schema. */
    xmlRelaxNGValidCtxtPtr vctxt = xmlRelaxNGNewValidCtxt(schema);
    if (vctxt == NULL) {
        xmlRelaxNGFree(schema);
        free(buf);
        return 0;
    }

    /* Hook fuzz error handlers to avoid noisy stderr and to use fuzz helpers. */
    xmlRelaxNGSetValidErrors(vctxt, (xmlRelaxNGValidityErrorFunc)xmlFuzzErrorFunc,
                             (xmlRelaxNGValidityWarningFunc)xmlFuzzErrorFunc, NULL);
    xmlRelaxNGSetValidStructuredErrors(vctxt, (xmlStructuredErrorFunc)xmlFuzzSErrorFunc, NULL);

    /* Try to locate a define to pass to xmlRelaxNGValidateDefinition. */
    xmlRelaxNGDefinePtr def = NULL;

    if (schema->topgrammar != NULL && schema->topgrammar->start != NULL) {
        def = schema->topgrammar->start;
    } else if (schema->defTab != NULL && schema->defNr > 0) {
        def = schema->defTab[0];
    } else {
        /*
         * As a fallback try to iterate defs hash table if present.
         * The layout of xmlRelaxNG contains a defs hash table, but its API
         * is internal; the above accesses cover the common cases. If no
         * define is available we skip the call.
         */
        def = NULL;
    }

    if (def != NULL) {
        /* xmlRelaxNGValidateDefinition is static in relaxng.c and is now callable
         * because relaxng.c was included in this translation unit. */
        /* Suppress any return value; we just want to exercise the code path. */
        (void) xmlRelaxNGValidateDefinition(vctxt, def);
    }

    /* Cleanup */
    xmlRelaxNGFreeValidCtxt(vctxt);
    xmlRelaxNGFree(schema);
    free(buf);

    /* Reset any injected failure state (fuzzer helpers may use this). */
    xmlFuzzResetFailure();

    return 0;
}
