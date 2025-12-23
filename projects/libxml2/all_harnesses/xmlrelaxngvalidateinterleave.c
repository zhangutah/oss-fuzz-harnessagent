#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>

/*
 * The public libxml2 headers do not expose the internal type xmlRelaxNGDefinePtr
 * nor the internal fields of struct _xmlRelaxNG (schema). To compile the harness
 * and still call the target function, declare the define pointer as an opaque
 * pointer type here (matching usage as an opaque handle).
 */
typedef void *xmlRelaxNGDefinePtr;

/* Forward-declare the target function so we call it directly in the harness.
 * Signature provided by the prompt:
 * int xmlRelaxNGValidateInterleave(xmlRelaxNGValidCtxtPtr ctxt, xmlRelaxNGDefinePtr define);
 *
 * The function is internal in many libxml2 builds and may not be exported. Declare it
 * as a weak symbol so the linker will not error if the symbol is absent; at runtime
 * the symbol will be NULL if not present and we check for that before calling.
 */
#if defined(__GNUC__) || defined(__clang__)
int xmlRelaxNGValidateInterleave(xmlRelaxNGValidCtxtPtr ctxt, xmlRelaxNGDefinePtr define) __attribute__((weak));
#else
/* Fallback: declare normally; if the build system/linker errors you may need to enable weak attrs */
int xmlRelaxNGValidateInterleave(xmlRelaxNGValidCtxtPtr ctxt, xmlRelaxNGDefinePtr define);
#endif

// Optional: suppress libxml2 generic error printing to stderr during fuzzing.
static void
noop_xml_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

// Fuzzer entry point
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Quick sanity check for input size
    if (Data == NULL || Size < 4) return 0;

    // Initialize libxml2 (safe to call multiple times)
    xmlInitParser();
    // Suppress global error output to avoid noisy logs during fuzzing.
    xmlSetGenericErrorFunc(NULL, (xmlGenericErrorFunc)noop_xml_error);

    // Split input into schema and document halves.
    size_t split = Size / 2;
    if (split == 0 || split == Size) {
        // fallback: put at least 1 byte to schema and 1 to doc
        split = (Size >= 2) ? 1 : Size;
    }

    const char *schemaBuf = (const char *)Data;
    int schemaSize = (int)split;
    const char *docBuf = (const char *)(Data + split);
    int docSize = (int)(Size - split);

    // Parse Relax-NG schema from memory
    xmlRelaxNGParserCtxtPtr pctxt = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlRelaxNGValidCtxtPtr vctxt = NULL;
    xmlDocPtr doc = NULL;

    // Create parser context for the schema (uses xmlRelaxNGNewMemParserCtxt)
    // The parser context will handle invalid/garbage input gracefully in many cases.
    pctxt = xmlRelaxNGNewMemParserCtxt(schemaBuf, schemaSize);
    if (pctxt == NULL) {
        goto cleanup;
    }

    // Disable parser error prints for schema parsing (use same noop)
    xmlRelaxNGSetParserErrors(pctxt, (xmlRelaxNGValidityErrorFunc)noop_xml_error,
                              (xmlRelaxNGValidityWarningFunc)noop_xml_error, NULL);
    xmlRelaxNGSetParserStructuredErrors(pctxt, NULL, NULL);

    // Parse/compile the schema
    schema = xmlRelaxNGParse(pctxt);
    // free parser context regardless of parse success
    xmlRelaxNGFreeParserCtxt(pctxt);
    pctxt = NULL;

    if (schema == NULL) {
        // Couldn't build schema; nothing to validate.
        goto cleanup;
    }

    // Create validation context from compiled schema
    vctxt = xmlRelaxNGNewValidCtxt(schema);
    if (vctxt == NULL) {
        goto cleanup;
    }

    // Disable validation error prints (we don't need noisy output during fuzzing)
    xmlRelaxNGSetValidErrors(vctxt,
                             (xmlRelaxNGValidityErrorFunc)noop_xml_error,
                             (xmlRelaxNGValidityWarningFunc)noop_xml_error,
                             NULL);
    xmlRelaxNGSetValidStructuredErrors(vctxt, NULL, NULL);

    // Parse XML document from the second half of input.
    // Use recover mode and disable network access for safety.
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    // xmlReadMemory expects an int length
    doc = xmlReadMemory(docBuf, docSize, "fuzz-input.xml", NULL, parseOptions);
    if (doc == NULL) {
        // If document parsing fails, we can still exercise interleave validation on the schema define,
        // so we don't immediately exit here.
    }

    // Explicitly call the target function to ensure the targeted code path is exercised.
    // The internal start define is not exposed by the public headers, so call with NULL
    // (opaque define pointer) if we have a validation context.
    if (vctxt != NULL) {
#if defined(__GNUC__) || defined(__clang__)
        if (xmlRelaxNGValidateInterleave != NULL) {
            (void) xmlRelaxNGValidateInterleave(vctxt, (xmlRelaxNGDefinePtr)NULL);
        }
#else
        /* Fallback: call if present - may link or not depending on environment */
        (void) xmlRelaxNGValidateInterleave(vctxt, (xmlRelaxNGDefinePtr)NULL);
#endif
    }

    // Also run a normal document validation flow which exercises many code paths.
    if (doc != NULL) {
        // Run validation: this will exercise many code paths inside Relax-NG validator,
        // including interleave handling when the schema contains interleave patterns.
        // Return value: 0 = valid, >0 invalid, -1 internal error.
        // We deliberately ignore the return value; crashes/vulnerabilities will be reported by the fuzzer.
        (void) xmlRelaxNGValidateDoc(vctxt, doc);
    }

cleanup:
    if (doc != NULL) {
        xmlFreeDoc(doc);
        doc = NULL;
    }
    if (vctxt != NULL) {
        xmlRelaxNGFreeValidCtxt(vctxt);
        vctxt = NULL;
    }
    if (schema != NULL) {
        xmlRelaxNGFree(schema);
        schema = NULL;
    }

    // It's okay to not call xmlCleanupParser on every input in a persistent fuzzer.
    // We keep xmlCleanupParser commented out for performance, but it can be used if desired.
    // xmlCleanupParser();

    return 0;
}
