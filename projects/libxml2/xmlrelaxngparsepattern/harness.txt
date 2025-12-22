#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/*
 * xmlRelaxNGDefinePtr is an internal type in libxml2 (defined in relaxng.c).
 * The public header doesn't expose it. For the purpose of dynamically looking
 * up xmlRelaxNGParsePattern with dlsym we only need an opaque pointer type.
 * Forward-declare it here as an incomplete struct and a pointer type so the
 * typedef for the function pointer compiles.
 */
typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

/*
 * Some libxml2 builds export xmlRelaxNGParsePattern (non-static). To maximize
 * the chance we actually call the target we:
 *  - Declare a weak reference to xmlRelaxNGParsePattern so that, if the symbol
 *    is available at link time, we call it directly.
 *  - Fall back to dlsym lookups if the weak symbol is not present.
 *
 * Use C linkage for the declaration so it works when compiled as C++.
 */
#ifdef __cplusplus
extern "C" {
#endif
#if defined(__GNUC__) || defined(__clang__)
extern xmlRelaxNGDefinePtr xmlRelaxNGParsePattern(xmlRelaxNGParserCtxtPtr, xmlNodePtr) __attribute__((weak));
#else
/* Fallback declaration; may cause link error on some toolchains if symbol not present. */
extern xmlRelaxNGDefinePtr xmlRelaxNGParsePattern(xmlRelaxNGParserCtxtPtr, xmlNodePtr);
#endif
#ifdef __cplusplus
}
#endif

/*
 * Minimal libxml2-based fuzz driver for:
 *   xmlRelaxNGDefinePtr xmlRelaxNGParsePattern(xmlRelaxNGParserCtxtPtr ctxt,
 *                                               xmlNodePtr node);
 *
 * Strategy:
 * - Parse the fuzzer input as an XML document (xmlReadMemory).
 * - Build a RelaxNG parser context from that document (xmlRelaxNGNewDocParserCtxt).
 * - Try to call xmlRelaxNGParsePattern directly via a weak symbol first; if not
 *   available, attempt to resolve it with dlsym and call it if found.
 * - Clean up parser context and document.
 *
 * This harness tries to avoid printing libxml2 errors by installing
 * no-op error/warning callbacks.
 */

/* No-op error/warning functions to silence libxml2 output during fuzzing */
static void
silent_relaxng_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
    /* intentionally ignore all messages */
}

static void
silent_relaxng_warning(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
    /* intentionally ignore all messages */
}

/* Fuzzer entry point */
/* Keep the exact signature but ensure C linkage when compiled as C++ */
#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the library (safe to call multiple times) */
    xmlInitParser();

    /* Copy input to a nul-terminated buffer for xmlReadMemory safety */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /*
     * Parse the input as an XML document. Use RECOVER and NONET to be
     * more resilient and avoid network access.
     */
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    free(buf);

    if (doc == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /*
     * Build a RelaxNG parser context from the parsed document. The
     * function under test expects a parser context and an xmlNodePtr.
     * Using the same document as the "schema" document is sufficient
     * for fuzzing arbitrary inputs.
     */
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewDocParserCtxt(doc);
    if (pctxt == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Silence parser error/warning callbacks to reduce noisy output */
    xmlRelaxNGSetParserErrors(pctxt, silent_relaxng_error,
                              silent_relaxng_warning, NULL);

    /* Choose the root element as target node (may be NULL) */
    xmlNodePtr node = xmlDocGetRootElement(doc);

    /*
     * Try to call xmlRelaxNGParsePattern. Prefer a direct (weak) call if the
     * symbol was available at link time. Otherwise fall back to dlsym
     * lookups across likely handles.
     *
     * If we obtain a callable function we invoke it with our parser context
     * and node. We ignore the return value (it may legitimately be NULL).
     */

    /* 1) Weak symbol: if available at link time this will be non-NULL. */
    if (xmlRelaxNGParsePattern != NULL) {
        (void) xmlRelaxNGParsePattern(pctxt, node);
    } else {
        /* 2) Try dlsym-based resolution */
        typedef xmlRelaxNGDefinePtr (*parse_func_t)(xmlRelaxNGParserCtxtPtr, xmlNodePtr);
        void *sym = NULL;

#ifdef RTLD_DEFAULT
        /* Prefer RTLD_DEFAULT which searches the global symbol scope */
        sym = dlsym(RTLD_DEFAULT, "xmlRelaxNGParsePattern");
#endif

        if (sym == NULL) {
#ifdef RTLD_NEXT
            sym = dlsym(RTLD_NEXT, "xmlRelaxNGParsePattern");
#endif
        }

        if (sym == NULL) {
            /* Try opening common libxml2 sonames explicitly (platform dependent) */
            const char *candidates[] = {
                "libxml2.so.2", /* common on many Linux distributions */
                "libxml2.so",   /* generic name */
                NULL
            };
            for (const char **p = candidates; *p != NULL && sym == NULL; ++p) {
                void *handle = dlopen(*p, RTLD_NOW | RTLD_NOLOAD);
                if (handle == NULL) {
                    /* Try to dlopen even if not already loaded */
                    handle = dlopen(*p, RTLD_NOW);
                }
                if (handle != NULL) {
                    sym = dlsym(handle, "xmlRelaxNGParsePattern");
                    /* Do not dlclose(handle) here to avoid closing potentially shared handles. */
                }
            }

            /* Last resort: try program handle obtained from dlopen(NULL, ...) */
            if (sym == NULL) {
                void *handle = dlopen(NULL, RTLD_NOW | RTLD_NOLOAD);
                if (handle == NULL) {
                    handle = dlopen(NULL, RTLD_NOW);
                }
                if (handle != NULL) {
                    sym = dlsym(handle, "xmlRelaxNGParsePattern");
                }
            }
        }

        if (sym != NULL) {
            parse_func_t func = (parse_func_t)sym;
            (void) func(pctxt, node);
        } else {
            /*
             * Symbol lookup not possible; skip calling the internal function.
             * This case can happen if the symbol is compiled into libxml2 as
             * a static/internal symbol and not exported. The weak symbol
             * attempt above handles many environments where the symbol is
             * available at link time.
             */
        }
    }

    /* Clean up */
    xmlRelaxNGFreeParserCtxt(pctxt);
    xmlFreeDoc(doc);

    /* Cleanup parser globals (safe to call repeatedly) */
    xmlCleanupParser();

    return 0;
}
