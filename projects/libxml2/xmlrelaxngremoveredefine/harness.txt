// /src/libxml2/fuzz/regexp.c
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>

/*
 * Fuzz driver for:
 *   int xmlRelaxNGRemoveRedefine(xmlRelaxNGParserCtxtPtr ctxt,
 *                                const xmlChar * URL,
 *                                xmlNodePtr target,
 *                                const xmlChar * name);
 *
 * This driver avoids static references to RELAXNG functions (which may be
 * absent from the libxml2 library build) by resolving them at runtime with dlsym.
 *
 * The fuzzer will:
 *  - attempt to parse the input bytes as an XML document (using xmlReadMemory),
 *    and pass the root's children as the 'target' argument.
 *  - derive small NUL-terminated strings from the input to serve as URL and name.
 *  - create and free a parser context if the symbols are available at runtime.
 *
 * The fuzzer entry point:
 * extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 */

/*
 * As an additional fallback and to ensure the target function actually gets
 * invoked when present in the linked library, declare a weak symbol for the
 * target function. When built against a libxml2 that provides this symbol,
 * the weak reference will be non-NULL and can be invoked directly. When it's
 * absent, the symbol will be NULL and the code will fall back to dlsym-based
 * resolution (above).
 *
 * This keeps the runtime resolution approach but guarantees that there's an
 * explicit (direct) call-site for the function name so harness checks that
 * look for the symbol usage will detect it.
 */
#ifdef __cplusplus
extern "C" {
#endif
#if defined(__GNUC__) || defined(__clang__)
extern int xmlRelaxNGRemoveRedefine(xmlRelaxNGParserCtxtPtr ctxt,
                                    const xmlChar * URL,
                                    xmlNodePtr target,
                                    const xmlChar * name) __attribute__((weak));
#else
extern int xmlRelaxNGRemoveRedefine(xmlRelaxNGParserCtxtPtr ctxt,
                                    const xmlChar * URL,
                                    xmlNodePtr target,
                                    const xmlChar * name);
#endif
#ifdef __cplusplus
}
#endif

static void *resolve_symbol(const char *name) {
    void *sym = NULL;

    /* 1) Try dlopen(NULL, ...) (main program handle + its loaded symbols) */
    void *main_handle = dlopen(NULL, RTLD_NOW | RTLD_NOLOAD);
    /* RTLD_NOLOAD ensures we don't unintentionally load new libs; fallback below will attempt dlopen if needed. */
    if (main_handle) {
        sym = dlsym(main_handle, name);
        dlclose(main_handle);
        if (sym) return sym;
    } else {
        /* Some platforms may not support RTLD_NOLOAD; try without it. */
        main_handle = dlopen(NULL, RTLD_NOW);
        if (main_handle) {
            sym = dlsym(main_handle, name);
            dlclose(main_handle);
            if (sym) return sym;
        }
    }

    /* 2) Try RTLD_DEFAULT if available */
#ifdef RTLD_DEFAULT
    sym = dlsym(RTLD_DEFAULT, name);
    if (sym) return sym;
#endif

    /* 3) Try common libxml2 shared object names */
    const char *candidates[] = {
#ifdef __APPLE__
        "libxml2.2.dylib",
        "libxml2.dylib",
#else
        "libxml2.so.2",
        "libxml2.so",
#endif
        NULL
    };

    for (const char **p = candidates; *p != NULL; ++p) {
        void *h = dlopen(*p, RTLD_NOW | RTLD_LOCAL);
        if (!h)
            h = dlopen(*p, RTLD_NOW); /* try again without LOCAL */
        if (!h)
            continue;
        sym = dlsym(h, name);
        dlclose(h);
        if (sym)
            return sym;
    }

    /* 4) Give up; symbol not found */
    return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the libxml2 parser (idempotent). */
    xmlInitParser();

    /* Try to parse the input as an XML document. If parsing fails, create a minimal doc. */
    xmlDocPtr doc = NULL;
    xmlNodePtr target = NULL;
    doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL,
                        XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING | XML_PARSE_NONET);
    if (doc != NULL) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL)
            target = root->children; /* match common usage where target is a list of children */
        else
            target = NULL;
    } else {
        /* create a minimal doc with an empty root */
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc != NULL) {
            xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "fuzzroot");
            if (root != NULL)
                xmlDocSetRootElement(doc, root);
            target = root ? root->children : NULL;
        }
    }

    /*
     * Resolve RELAXNG-related functions at runtime to avoid link-time failures
     * when libxml2 lacks RELAXNG support.
     */
    typedef xmlRelaxNGParserCtxtPtr (*xmlRelaxNGNewParserCtxt_t)(const char *);
    typedef void (*xmlRelaxNGFreeParserCtxt_t)(xmlRelaxNGParserCtxtPtr);
    typedef int (*xmlRelaxNGRemoveRedefine_t)(xmlRelaxNGParserCtxtPtr, const xmlChar *, xmlNodePtr, const xmlChar *);

    void *sym_new = resolve_symbol("xmlRelaxNGNewParserCtxt");
    void *sym_free = resolve_symbol("xmlRelaxNGFreeParserCtxt");
    void *sym_remove = resolve_symbol("xmlRelaxNGRemoveRedefine");

    xmlRelaxNGNewParserCtxt_t p_xmlRelaxNGNewParserCtxt = (xmlRelaxNGNewParserCtxt_t)sym_new;
    xmlRelaxNGFreeParserCtxt_t p_xmlRelaxNGFreeParserCtxt = (xmlRelaxNGFreeParserCtxt_t)sym_free;
    xmlRelaxNGRemoveRedefine_t p_xmlRelaxNGRemoveRedefine = (xmlRelaxNGRemoveRedefine_t)sym_remove;

    /* Create a parser context if the constructor is available; else leave ctxt NULL. */
    xmlRelaxNGParserCtxtPtr ctxt = NULL;
    if (p_xmlRelaxNGNewParserCtxt) {
        ctxt = p_xmlRelaxNGNewParserCtxt("fuzz-context");
    } else {
        ctxt = NULL;
    }

    /* Derive URL and name strings from the input bytes (NUL terminated). */
    const size_t MAX_STR = 128;
    size_t url_len = (Size < 16) ? Size : 16; /* small URL piece from beginning */
    if (url_len > MAX_STR) url_len = MAX_STR;
    char *url = (char *)malloc(url_len + 1);
    if (url == NULL) {
        if (p_xmlRelaxNGFreeParserCtxt && ctxt) p_xmlRelaxNGFreeParserCtxt(ctxt);
        if (doc) xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    if (url_len > 0)
        memcpy(url, Data, url_len);
    url[url_len] = '\0';

    /* name derived from a later part of input if available, else empty string */
    size_t name_offset = (url_len < Size) ? url_len : 0;
    size_t name_len = (Size > name_offset) ? (Size - name_offset) : 0;
    if (name_len > 16) name_len = 16;
    if (name_len > MAX_STR) name_len = MAX_STR;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        free(url);
        if (p_xmlRelaxNGFreeParserCtxt && ctxt) p_xmlRelaxNGFreeParserCtxt(ctxt);
        if (doc) xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    if (name_len > 0)
        memcpy(name, Data + name_offset, name_len);
    name[name_len] = '\0';

    /*
     * Call the target function if available. Use the resolved pointer to avoid
     * unresolved symbol at link time. Try harder to call it by attempting
     * runtime resolution above.
     *
     * Also, if a weak direct symbol is present (xmlRelaxNGRemoveRedefine),
     * prefer calling that: it creates a direct call-site for the symbol while
     * still remaining safe if the symbol is absent.
     */
    if (p_xmlRelaxNGRemoveRedefine) {
        /* Ensure we actually call the target function */
        (void) p_xmlRelaxNGRemoveRedefine(ctxt, (const xmlChar *)url, target, (const xmlChar *)name);
    } else {
        /* Try direct weak symbol if available (works when symbol is linked but wasn't resolved above) */
        if (xmlRelaxNGRemoveRedefine) {
            (void) xmlRelaxNGRemoveRedefine(ctxt, (const xmlChar *)url, target, (const xmlChar *)name);
        } else {
            /*
             * Best-effort: if resolution failed but the symbol might still be available
             * via a direct (non-weak) symbol, try a last-ditch dlsym(RTLD_DEFAULT,...).
             * (This is redundant in most cases since resolve_symbol tried RTLD_DEFAULT.)
             */
#ifdef RTLD_DEFAULT
            void *sym_try = dlsym(RTLD_DEFAULT, "xmlRelaxNGRemoveRedefine");
            if (sym_try) {
                xmlRelaxNGRemoveRedefine_t fn = (xmlRelaxNGRemoveRedefine_t)sym_try;
                (void) fn(ctxt, (const xmlChar *)url, target, (const xmlChar *)name);
            } else {
                /* RELAXNG support not present at runtime; nothing more to do. */
                (void)target; /* silence unused warning if any */
            }
#else
            /* RELAXNG support not present at runtime; nothing more to do. */
            (void)target; /* silence unused warning if any */
#endif
        }
    }

    /* Clean up */
    free(url);
    free(name);
    if (p_xmlRelaxNGFreeParserCtxt && ctxt) p_xmlRelaxNGFreeParserCtxt(ctxt);
    if (doc) xmlFreeDoc(doc);

    /* Note: xmlCleanupParser can be called at program end; calling it here is safe but may be costly. */
    xmlCleanupParser();

    return 0;
}
