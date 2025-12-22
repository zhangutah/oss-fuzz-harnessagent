#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/*
 * Fuzz driver for:
 *   xmlRelaxNGDefinePtr xmlRelaxNGParseNameClass(xmlRelaxNGParserCtxtPtr ctxt,
 *                                                xmlNodePtr node,
 *                                                xmlRelaxNGDefinePtr def);
 *
 * Strategy:
 * - Parse the input bytes as an XML document using libxml2 (xmlReadMemory).
 * - Create a Relax-NG memory parser context with the same bytes (xmlRelaxNGNewMemParserCtxt).
 * - Attempt to call xmlRelaxNGParseNameClass if available via a weak symbol (linked)
 *   and fall back to dlsym if not.
 * - Cleanup allocated structures.
 *
 * The driver is defensive: it tolerates missing root/doc and frees everything that
 * the public API provides. If LIBXML_RELAXNG_ENABLED is not defined at build time,
 * the fuzzer entry is a no-op.
 */

#ifdef LIBXML_RELAXNG_ENABLED

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the XML library (no-op if already done) */
    xmlInitParser();

    /* Parse the fuzz input as an XML document. Use recover and silence parser errors/warnings. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data,
                                 (int)Size,
                                 "fuzz-input.xml",
                                 NULL,
                                 XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        /* Still attempt to create a Relax-NG parser context and exit gracefully */
        xmlRelaxNGParserCtxtPtr rctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
        if (rctxt != NULL) {
            /* No node to call on; just free the parser context */
            xmlRelaxNGFreeParserCtxt(rctxt);
        }
        xmlCleanupParser();
        return 0;
    }

    /* Get the document root element */
    xmlNodePtr root = xmlDocGetRootElement(doc);

    /* Create a Relax-NG parser context from the same buffer */
    xmlRelaxNGParserCtxtPtr rctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);

    if (rctxt != NULL) {
        /*
         * xmlRelaxNGParseNameClass and xmlRelaxNGDefinePtr are internal in some
         * libxml2 builds (often static), so they might not be available for direct
         * linking. To avoid compile-time or link-time failures, we:
         *  - First try to call a weakly-declared symbol (works if the symbol is linked).
         *  - Otherwise fall back to dlsym lookup like before.
         *
         * The expected function signature is:
         *   xmlRelaxNGDefinePtr xmlRelaxNGParseNameClass(xmlRelaxNGParserCtxtPtr, xmlNodePtr, xmlRelaxNGDefinePtr);
         */

        /* Declare a weak reference to the symbol. If the symbol is present in the binary,
         * this weak reference will resolve and we can call it directly.
         *
         * Use opaque void* for the return and the last parameter because
         * xmlRelaxNGDefinePtr is internal and not exposed publicly.
         */
#if defined(__GNUC__)
        extern void *xmlRelaxNGParseNameClass(xmlRelaxNGParserCtxtPtr, xmlNodePtr, void *) __attribute__((weak));
#else
        extern void *xmlRelaxNGParseNameClass(xmlRelaxNGParserCtxtPtr, xmlNodePtr, void *);
#endif

        if ((void*)xmlRelaxNGParseNameClass != NULL) {
            /* Call with NULL for the last parameter (opaque define pointer) */
            (void) xmlRelaxNGParseNameClass(rctxt, root, NULL);
        } else {
            /* Fallback to dlsym lookup in the global symbol table. Use RTLD_DEFAULT if available, otherwise dlopen(NULL,...) */
            typedef void *(*xmlRelaxNGParseNameClassFn)(xmlRelaxNGParserCtxtPtr, xmlNodePtr, void *);
            void *sym = NULL;
#ifdef RTLD_DEFAULT
            sym = dlsym(RTLD_DEFAULT, "xmlRelaxNGParseNameClass");
#else
            void *global_handle = dlopen(NULL, RTLD_LAZY);
            if (global_handle != NULL) {
                sym = dlsym(global_handle, "xmlRelaxNGParseNameClass");
                /* It's safe to close the handle obtained from dlopen(NULL, ...);
                   the symbol will remain resolved for our process. */
                dlclose(global_handle);
            } else {
                /* As a last-ditch attempt, try plain dlsym with NULL (not portable but sometimes works) */
                sym = dlsym(NULL, "xmlRelaxNGParseNameClass");
            }
#endif
            if (sym != NULL) {
                xmlRelaxNGParseNameClassFn fn = (xmlRelaxNGParseNameClassFn)sym;
                (void) fn(rctxt, root, NULL);
            } else {
                /* Symbol not found: nothing to do. */
            }
        }

        /* Free the parser context */
        xmlRelaxNGFreeParserCtxt(rctxt);
    }

    /* Cleanup parsed document */
    xmlFreeDoc(doc);

    /* Cleanup parser global state */
    xmlCleanupParser();

    return 0;
}

#else /* LIBXML_RELAXNG_ENABLED */

/* If Relax-NG support is not compiled in, provide a no-op fuzzer entry so the harness compiles. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    (void)Data;
    (void)Size;
    return 0;
}

#endif /* LIBXML_RELAXNG_ENABLED */