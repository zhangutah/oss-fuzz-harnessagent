// Fixed harness: ensure xmlRelaxNGCleanupAttributes is actually called when available.
//
// Changes:
// - Add a weak declaration for xmlRelaxNGCleanupAttributes so that if the symbol
//   is available at link time we call it directly.
// - If the weak symbol is not present, fall back to the existing dlsym-based lookup.
// - Preserve original behavior and cleanup paths.
//
// This file keeps the same LLVMFuzzerTestOneInput signature.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Weak declare the target function so that if libxml2 was linked with
 * Relax-NG support we will call it directly. On platforms/toolchains that
 * don't support weak symbols this attribute will be ignored, and the
 * pointer test below will behave appropriately.
 *
 * Signature:
 *   void xmlRelaxNGCleanupAttributes(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
 */
#if defined(__GNUC__) || defined(__clang__)
extern void xmlRelaxNGCleanupAttributes(xmlRelaxNGParserCtxtPtr, xmlNodePtr) __attribute__((weak));
#else
/* If no weak attribute support, still declare it (may produce link error
 * if absent when called); however we only call it if the symbol resolves
 * (we check for non-NULL). */
extern void xmlRelaxNGCleanupAttributes(xmlRelaxNGParserCtxtPtr, xmlNodePtr);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml and silence generic errors to avoid noisy output during fuzzing */
    xmlInitParser();
    xmlSetStructuredErrorFunc(NULL, NULL); /* disable structured errors */
    xmlSetGenericErrorFunc(NULL, NULL);    /* disable generic errors */

    /* Try to parse the input as an XML document */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                 "fuzz-input.xml", NULL,
                                 XML_PARSE_RECOVER | XML_PARSE_NONET |
                                 XML_PARSE_NOERROR | XML_PARSE_NOWARNING);

    xmlDocPtr syntheticDoc = NULL;
    xmlNodePtr node = NULL;

    if (doc != NULL) {
        node = xmlDocGetRootElement(doc);
    } else {
        /* If parsing failed, create a minimal document with a root node */
        syntheticDoc = xmlNewDoc((const xmlChar *)"1.0");
        if (syntheticDoc != NULL) {
            node = xmlNewDocNode(syntheticDoc, NULL, (const xmlChar *)"root", NULL);
            if (node)
                xmlDocSetRootElement(syntheticDoc, node);
        }
    }

    /* If we still don't have a node, nothing to do */
    if (node == NULL) {
        if (doc) xmlFreeDoc(doc);
        if (syntheticDoc) xmlFreeDoc(syntheticDoc);
        xmlCleanupParser();
        return 0;
    }

    /*
     * First, if the weak symbol resolved at link-time, call it directly.
     * This ensures the function is actually invoked when available.
     */
#if defined(__GNUC__) || defined(__clang__)
    if (&xmlRelaxNGCleanupAttributes != NULL) {
        /* Call with NULL context (safe default) and the node we prepared */
        xmlRelaxNGCleanupAttributes(NULL, node);
    } else
#endif
    {
        /*
         * Otherwise, try to resolve the symbol at runtime via dlsym.
         * Try several strategies to be robust across platforms.
         */
        typedef void (*cleanup_fn_t)(xmlRelaxNGParserCtxtPtr, xmlNodePtr);
        cleanup_fn_t cleanup = NULL;

        /* First try RTLD_DEFAULT via dlsym if available (POSIX doesn't require it, but many do) */
#ifdef RTLD_DEFAULT
        {
            void *sym = dlsym(RTLD_DEFAULT, "xmlRelaxNGCleanupAttributes");
            if (sym != NULL)
                cleanup = (cleanup_fn_t)sym;
        }
#endif

        /* If not found, try to use the main program handle (dlopen(NULL, ...)) */
        if (cleanup == NULL) {
            void *handle = dlopen(NULL, RTLD_NOW);
            if (handle != NULL) {
                void *sym = dlsym(handle, "xmlRelaxNGCleanupAttributes");
                if (sym != NULL)
                    cleanup = (cleanup_fn_t)sym;
                dlclose(handle);
            }
        }

        /* If still not found, try plain dlsym(NULL, ...) as a last resort on some platforms */
        if (cleanup == NULL) {
            void *sym = dlsym(NULL, "xmlRelaxNGCleanupAttributes");
            if (sym != NULL)
                cleanup = (cleanup_fn_t)sym;
        }

        if (cleanup) {
            cleanup(NULL, node);
        }
    }

    /* Clean up */
    if (doc)
        xmlFreeDoc(doc);
    if (syntheticDoc)
        xmlFreeDoc(syntheticDoc);

    /* Clean global parser state */
    xmlCleanupParser();

    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
