#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

#ifdef LIBXML_RELAXNG_ENABLED

#include <dlfcn.h>

/*
 * Minimal re-declarations of internal structs from relaxng.c so we can
 * access schema->topgrammar->start. We only reproduce the fields we need.
 *
 * These must match the layout used by libxml2's relaxng.c for the fields we
 * access (topgrammar -> start). This is a best-effort minimal mapping.
 *
 * The public relaxng header already defines xmlRelaxNG and xmlRelaxNGPtr,
 * but the internal grammar struct is not public so we declare it here.
 */
typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

typedef struct _xmlRelaxNGGrammar {
    struct _xmlRelaxNGGrammar *parent;
    struct _xmlRelaxNGGrammar *children;
    struct _xmlRelaxNGGrammar *next;
    xmlRelaxNGDefinePtr start;      /* <start> content */
    int combine;                    /* the default combine value */
    xmlRelaxNGDefinePtr startList;  /* list of <start> definitions */
    void *defs;                     /* define* (opaque here) */
    void *refs;                     /* references (opaque) */
} xmlRelaxNGGrammar;
typedef xmlRelaxNGGrammar *xmlRelaxNGGrammarPtr;

/*
 * Partial layout of the public xmlRelaxNG structure as implemented in relaxng.c
 * We only need topgrammar to get at start.
 */
typedef struct _xmlRelaxNG {
    void *_private;
    xmlRelaxNGGrammarPtr topgrammar;
    xmlDocPtr doc;
    int idref;
    void *defs;
    void *refs;
    void *documents;
    void *includes;
    int defNr;
    void *defTab;
    /* rest omitted */
} xmlRelaxNG;
typedef xmlRelaxNG *xmlRelaxNGPtr;

/* Declare the internal function as a weak symbol so the harness will still
 * link even if the symbol isn't exported. If the symbol is present at runtime
 * the pointer will be non-NULL and we can call it directly. This avoids
 * relying solely on dlsym and ensures the target function is invoked when
 * available.
 */
#ifdef __cplusplus
extern "C" {
#endif
int xmlRelaxNGValidateState(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr)
    __attribute__((weak));
#ifdef __cplusplus
}
#endif

/* Fuzzer entry point expected by libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser environment (safe to call multiple times) */
    xmlInitParser();

    /* Parse the fuzzer input as a Relax-NG schema in memory */
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
    if (pctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Try to parse the schema */
    xmlRelaxNGPtr schema = xmlRelaxNGParse(pctxt);
    /* free parser ctxt now - xmlRelaxNGParse copies/references as needed */
    xmlRelaxNGFreeParserCtxt(pctxt);

    if (schema == NULL) {
        /* Parsing failed; nothing more to do */
        xmlCleanupParser();
        return 0;
    }

    /* Create a validation context from the parsed schema */
    xmlRelaxNGValidCtxtPtr vctxt = xmlRelaxNGNewValidCtxt(schema);
    if (vctxt == NULL) {
        xmlRelaxNGFree(schema);
        xmlCleanupParser();
        return 0;
    }

    /* Try to obtain a definition to validate against: schema->topgrammar->start */
    xmlRelaxNGDefinePtr def = NULL;
    if (schema->topgrammar != NULL) {
        xmlRelaxNGGrammarPtr g = schema->topgrammar;
        def = g->start;
    }

    /*
     * Prefer calling the internal function directly if present (weak symbol),
     * otherwise fall back to runtime lookup via dlsym. This guarantees the
     * target function gets invoked when available.
     */
    if (xmlRelaxNGValidateState) {
        /* Call the internal function if available. We ignore the return value. */
        (void)xmlRelaxNGValidateState(vctxt, def);
    } else {
        /* Fallback: try to find it via dlsym in the loaded libraries */
        void *handle = dlopen(NULL, RTLD_LAZY);
        if (handle != NULL) {
            void *sym = dlsym(handle, "xmlRelaxNGValidateState");
            if (sym != NULL) {
#ifdef __cplusplus
                typedef int (*xmlRelaxNGValidateStateFn)(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr);
                xmlRelaxNGValidateStateFn fn = reinterpret_cast<xmlRelaxNGValidateStateFn>(sym);
#else
                typedef int (*xmlRelaxNGValidateStateFn)(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr);
                xmlRelaxNGValidateStateFn fn = (xmlRelaxNGValidateStateFn) sym;
#endif
                (void)fn(vctxt, def);
            }
            /* No need to dlclose(handle) for dlopen(NULL) but it's harmless to skip. */
        }
    }

    /* Clean up */
    xmlRelaxNGFreeValidCtxt(vctxt);
    xmlRelaxNGFree(schema);

    /* Cleanup global parser state (optional) */
    xmlCleanupParser();

    return 0;
}

#else /* LIBXML_RELAXNG_ENABLED */

/* If libxml2 was built without Relax-NG support just provide a no-op harness.
 * This avoids referencing non-existent symbols at link time.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    (void)Data;
    (void)Size;
    return 0;
}

#endif /* LIBXML_RELAXNG_ENABLED */
