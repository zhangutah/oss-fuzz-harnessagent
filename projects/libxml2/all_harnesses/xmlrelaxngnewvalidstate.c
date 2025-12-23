#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/*
 * xmlRelaxNGNewValidState is not part of the public header (relaxng.h),
 * so declare a compatible prototype here. We declare the return type as
 * void* to avoid needing the internal struct definition; the first
 * parameter uses the public xmlRelaxNGValidCtxtPtr type from relaxng.h.
 *
 * Do NOT provide a local definition here. The real implementation in the
 * project's relaxng.c should be used at runtime. Providing a stub locally
 * masks the real function and leads to incorrect behavior during fuzzing.
 *
 * We will try two ways to call it:
 * 1) If the symbol is available at link time as a weak symbol, call it
 *    directly (checking it's non-NULL).
 * 2) Otherwise fall back to resolving it at runtime with dlsym().
 *
 * Declaring it weak avoids creating a hard link-time dependency when the
 * symbol is not exported by the libxml2 build.
 */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
extern void *xmlRelaxNGNewValidState(xmlRelaxNGValidCtxtPtr ctxt, xmlNodePtr node) __attribute__((weak));
#else
/* No weak attribute available: declare normally (builds in environments where symbol exists) */
extern void *xmlRelaxNGNewValidState(xmlRelaxNGValidCtxtPtr ctxt, xmlNodePtr node);
#endif

#ifdef __cplusplus
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /*
     * Initialize the libxml2 parser. It's safe to call multiple times.
     */
    xmlInitParser();

    /*
     * Parse the fuzz input as XML. Use recover and nonet to limit side effects.
     */
    int docSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, docSize,
                                  "fuzz-input.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET |
                                  XML_PARSE_NOERROR | XML_PARSE_NOWARNING);

    xmlDocPtr tmpdoc_for_manual = NULL;
    xmlNodePtr node = NULL;

    if (doc != NULL) {
        node = xmlDocGetRootElement(doc);
        /*
         * If parsing produced a doc but no root element, synthesize a node
         * attached to that doc to exercise the code path.
         */
        if (node == NULL) {
            node = xmlNewDocNode(doc, NULL, BAD_CAST "fuzz", NULL);
            xmlDocSetRootElement(doc, node);
            /* set content from Data (may be non-UTF8; use len-aware API to avoid reading past buffer) */
            int set_len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
            xmlNodeSetContentLen(node, (const xmlChar *)Data, set_len);
        }
    } else {
        /*
         * If parsing fails, build a minimal doc + node containing the raw
         * fuzz data. This ensures we always pass a node pointer to the
         * target function.
         */
        tmpdoc_for_manual = xmlNewDoc(BAD_CAST "1.0");
        if (tmpdoc_for_manual == NULL) {
            xmlCleanupParser();
            return 0;
        }
        node = xmlNewDocNode(tmpdoc_for_manual, NULL, BAD_CAST "fuzz", NULL);
        if (node == NULL) {
            xmlFreeDoc(tmpdoc_for_manual);
            xmlCleanupParser();
            return 0;
        }
        xmlDocSetRootElement(tmpdoc_for_manual, node);
        /* limit content size to avoid huge allocations */
        size_t set_len = Size;
        const size_t MAX_CONTENT = 1 << 20; /* 1MB */
        if (set_len > MAX_CONTENT) set_len = MAX_CONTENT;
        /* copy truncated data into a temporary buffer and set as content */
        char *buf = (char *)xmlMalloc(set_len + 1);
        if (buf != NULL) {
            memcpy(buf, Data, set_len);
            buf[set_len] = '\0';
            xmlNodeSetContent(node, (const xmlChar *)buf);
            xmlFree(buf);
        } else {
            /* fallback: set no content */
        }
        doc = tmpdoc_for_manual;
    }

    /*
     * Create a validation context. Passing NULL for the schema is tolerated
     * by the public API for constructing a context object; the target
     * function will handle a NULL or incomplete context defensively.
     */
    xmlRelaxNGValidCtxtPtr vctxt = xmlRelaxNGNewValidCtxt(NULL);
    if (vctxt != NULL) {
        /*
         * Call the internal target function with the created context and node.
         * The return value is an internal opaque pointer; we do not dereference it.
         *
         * We prefer calling the symbol directly if available at link time as a
         * weak symbol. If not, we fall back to resolving it at runtime via dlsym().
         */
        void *st = NULL;
        /* Protect the call in case of unexpected NULL node */
        if (node != NULL) {
            /* First try direct (weak) symbol call if available */
            if (&xmlRelaxNGNewValidState != NULL) {
                /* &xmlRelaxNGNewValidState may be NULL at runtime if it was not provided */
                /* Some platforms might not support weak symbols; in that case this symbol is likely present */
                /* Call directly if non-NULL */
                if (xmlRelaxNGNewValidState != NULL) {
                    st = xmlRelaxNGNewValidState(vctxt, node);
                    (void)st;
                }
            }

            /* If direct call didn't happen (symbol not available), try dlsym fallback */
            if (st == NULL) {
                typedef void *(*xmlRelaxNGNewValidState_fn)(xmlRelaxNGValidCtxtPtr, xmlNodePtr);
                xmlRelaxNGNewValidState_fn fn = NULL;

                /* Try to get the symbol from the main program / loaded libraries */
                void *handle = dlopen(NULL, RTLD_LAZY);
                if (handle != NULL) {
                    /* Clear any existing error */
                    dlerror();
                    fn = (xmlRelaxNGNewValidState_fn)dlsym(handle, "xmlRelaxNGNewValidState");
                    /* it's safe to dlclose the handle from dlopen(NULL,...) but not strictly necessary */
                    dlclose(handle);
                } else {
                    /* Fallback: try the special handle RTLD_DEFAULT (may be supported) */
#if defined(RTLD_DEFAULT)
                    dlerror();
                    fn = (xmlRelaxNGNewValidState_fn)dlsym(RTLD_DEFAULT, "xmlRelaxNGNewValidState");
#endif
                }

                if (fn != NULL) {
                    st = fn(vctxt, node);
                    (void)st;
                } else {
                    /* Symbol not available in this libxml2 build; nothing to call. */
                }
            }
        }
        /* Free the validation context which should cleanup associated state */
        xmlRelaxNGFreeValidCtxt(vctxt);
    }

    /*
     * Free created document/node
     */
    if (doc != NULL)
        xmlFreeDoc(doc);

    /* Cleanup global parser state (safe for fuzzing single-process) */
    xmlCleanupParser();

    return 0;
}
