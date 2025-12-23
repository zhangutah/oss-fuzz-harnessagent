/* Enable GNU extensions so RTLD_DEFAULT is defined in dlfcn.h */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>    // for dlsym, dlopen, dlclose

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/*
 * The target function xmlRelaxNGParseValue is internal to libxml2 and may
 * not be exported for direct linking. To avoid an undefined reference at
 * link time we look it up at runtime using dlsym and call it if available.
 *
 * On builds where the symbol is available at link time (for example when
 * the harness is built together with the library objects), calling the
 * function directly produces coverage reliably. To support both cases we
 * declare a weak reference to the symbol and call it if present; otherwise
 * fall back to dlsym as before.
 *
 * The real return type of xmlRelaxNGParseValue is xmlRelaxNGDefinePtr which
 * is an internal type not present in the public headers exposed to this
 * harness. Use void * for the weak declaration (compatible with pointer
 * returns) and use a matching function-pointer typedef when resolving
 * dynamically.
 */
#if defined(__GNUC__)
extern void *xmlRelaxNGParseValue(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) __attribute__((weak));
#else
extern void *xmlRelaxNGParseValue(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
#endif

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the libxml2 library (safe to call multiple times). */
    xmlInitParser();

    /* Limit size to INT_MAX for APIs taking int length */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Create a Relax-NG parser context from the input buffer. */
    xmlRelaxNGParserCtxtPtr rngctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, len);

    /* Parse the input buffer as an XML document to obtain an xmlNodePtr.
     * Use flags to avoid network access and to suppress noisy errors/warnings.
     */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOWARNING | XML_PARSE_NOERROR;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, len, "fuzz.xml", NULL, parseOptions);

    /* Get the document root node to pass to xmlRelaxNGParseValue. */
    xmlNodePtr root = NULL;
    if (doc != NULL) {
        root = xmlDocGetRootElement(doc);
    }

    /* First, try calling the symbol directly if it's available at link time
     * via the weak symbol. This ensures coverage when possible.
     *
     * xmlRelaxNGParseValue was declared above returning void * to avoid
     * depending on an internal typedef. If the weak symbol is present,
     * call it (ignoring the returned pointer).
     */
    if (&xmlRelaxNGParseValue != NULL && xmlRelaxNGParseValue != NULL) {
        /* Call the target function directly. */
        (void)xmlRelaxNGParseValue(rngctxt, root);
    } else {
        /* Otherwise attempt to locate xmlRelaxNGParseValue at runtime and call it if found. */
        typedef void *(*xmlRelaxNGParseValue_fn)(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
        xmlRelaxNGParseValue_fn parseValue = NULL;

        /* Use RTLD_DEFAULT (requires _GNU_SOURCE) to search global symbol table first. */
        void *sym = dlsym(RTLD_DEFAULT, "xmlRelaxNGParseValue");
        if (sym != NULL) {
            parseValue = (xmlRelaxNGParseValue_fn)sym;
        } else {
            /* If not found in the main program, try opening the libxml2 shared library
             * and resolving the symbol from it. The soname may vary; try common ones.
             */
            const char *candidates[] = {
                "libxml2.so.2",
                "libxml2.so",
                NULL
            };
            for (const char **p = candidates; *p != NULL && parseValue == NULL; ++p) {
                void *handle = dlopen(*p, RTLD_LAZY | RTLD_LOCAL);
                if (handle) {
                    sym = dlsym(handle, "xmlRelaxNGParseValue");
                    if (sym) {
                        parseValue = (xmlRelaxNGParseValue_fn)sym;
                    }
                    dlclose(handle);
                }
            }
        }

        if (parseValue != NULL) {
            /* Call the target function resolved at runtime. */
            (void)parseValue(rngctxt, root);
        } else {
            /* If the symbol is not available, we still exercised parsing and
             * parser-context construction. No-op the target call.
             */
        }
    }

    /* Cleanup */
    if (rngctxt != NULL)
        xmlRelaxNGFreeParserCtxt(rngctxt);
    if (doc != NULL)
        xmlFreeDoc(doc);

    /* Optional global cleanup for libxml2 (no-op in many environments but safe). */
    xmlCleanupParser();

    return 0;
}
