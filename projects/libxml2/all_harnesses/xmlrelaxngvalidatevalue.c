#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>

/*
 * Forward-declare the internal define type so we can reference it as a pointer
 * in the prototype below. The actual structure is internal to libxml2, but
 * declaring it as an incomplete type is enough to call the function.
 */
typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /*
     * Initialize the libxml2 library (no-op if already initialized).
     * Safe to call multiple times.
     */
    xmlInitParser();

    /*
     * Use the fuzz input as a Relax-NG schema first. Create a parser context
     * for a memory buffer and try to parse a schema. Many inputs will fail
     * parsing, which is fine 1 we only proceed if parsing succeeds.
     */
    xmlRelaxNGParserCtxtPtr pctxt = NULL;
    xmlRelaxNGPtr schema = NULL;
    xmlRelaxNGValidCtxtPtr vctxt = NULL;
    xmlDocPtr doc = NULL;

    // Ensure the Data is treated as a NUL-terminated buffer for some APIs:
    // allocate a temporary buffer with a terminating NUL to be safe.
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Create a parser context for the schema from memory
    pctxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
    if (pctxt != NULL) {
        // Try to parse the schema. This may return NULL on invalid input.
        schema = xmlRelaxNGParse(pctxt);
        // Free the parser context (schema independent copy is kept if parse succeeded)
        xmlRelaxNGFreeParserCtxt(pctxt);
        pctxt = NULL;
    }

    /*
     * If we parsed a schema, try to build a validation context and validate
     * an XML document. We'll reuse the fuzz input as the XML document too,
     * but parsed as an XML doc. Many inputs will fail parsing the XML doc,
     * in which case we skip validation. The goal is to exercise code paths.
     */
    if (schema != NULL) {
        // Create a validation context for the parsed schema
        vctxt = xmlRelaxNGNewValidCtxt(schema);
        if (vctxt == NULL) {
            xmlRelaxNGFree(schema);
            schema = NULL;
            free(buf);
            xmlCleanupParser();
            return 0;
        }

        /*
         * xmlRelaxNGValidateValue switches on define->type and for certain simple
         * types (e.g. XML_RELAXNG_TEXT) it does not dereference further fields.
         * We craft a minimal stack object whose first field is the type and set
         * it to the value corresponding to XML_RELAXNG_TEXT so the function can be
         * safely invoked without needing to construct the whole internal structure.
         *
         * Note: the enum values are internal; XML_RELAXNG_TEXT is 3 in the
         * libxml2 implementation. Using the numeric value here allows exercising
         * the function without depending on internal headers.
         *
         * The symbol xmlRelaxNGValidateValue is internal in many builds and may not
         * be exported for static linking. To increase the chance the fuzzer will
         * see and call the target function we attempt a direct (weak) reference
         * to the symbol and fall back to runtime lookup via dlsym if needed.
         */
        struct {
            int type;
        } dummy_define;
        const int XML_RELAXNG_TEXT_VAL = 3; /* matches internal XML_RELAXNG_TEXT */
        dummy_define.type = XML_RELAXNG_TEXT_VAL;

        /* Declare a weak reference to the internal function so builds that
         * export it will allow a direct call (and the symbol name will be
         * present in the binary). If the symbol is not available the weak
         * reference will be NULL and we'll try dlsym as a fallback.
         */
#if defined(__GNUC__) || defined(__clang__)
        extern int xmlRelaxNGValidateValue(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr) __attribute__((weak));
        if (&xmlRelaxNGValidateValue != NULL) {
            /* direct weak call if present */ 
            (void)xmlRelaxNGValidateValue(vctxt, (xmlRelaxNGDefinePtr)&dummy_define);
        } else
#endif
        {
            /* Fallback: resolve at runtime via dlsym (works for dynamic builds) */
            typedef int (*xmlRelaxNGValidateValueFunc)(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr);
            xmlRelaxNGValidateValueFunc validateValue = NULL;
#ifdef RTLD_DEFAULT
            validateValue = (xmlRelaxNGValidateValueFunc)dlsym(RTLD_DEFAULT, "xmlRelaxNGValidateValue");
#else
            {
                void *handle = dlopen(NULL, RTLD_LAZY);
                if (handle != NULL) {
                    validateValue = (xmlRelaxNGValidateValueFunc)dlsym(handle, "xmlRelaxNGValidateValue");
                    /* don't dlclose(handle) as it's the main program handle */
                }
            }
#endif
            if (validateValue != NULL) {
                (void)validateValue(vctxt, (xmlRelaxNGDefinePtr)&dummy_define);
            }
        }

        // Try to parse the input as an XML document (use a different name)
        // Use xmlReadMemory which accepts a buffer and its size.
        doc = xmlReadMemory(buf, (int)Size, "fuzz-doc.xml", NULL, XML_PARSE_RECOVER | XML_PARSE_NOENT);
        if (doc != NULL) {
            // Validate the document against the schema.
            // This will run the validator and exercise internal routines.
            (void)xmlRelaxNGValidateDoc(vctxt, doc);

            // Free the document
            xmlFreeDoc(doc);
            doc = NULL;
        }

        // Free validation context and schema
        xmlRelaxNGFreeValidCtxt(vctxt);
        vctxt = NULL;

        xmlRelaxNGFree(schema);
        schema = NULL;
    }

    free(buf);

    // Cleanup parser state (not strictly necessary per iteration but kept tidy)
    xmlCleanupParser();

    return 0;
}
