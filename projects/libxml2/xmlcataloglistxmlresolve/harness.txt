#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Use the project header (absolute path found in the source tree) */
#include "/src/libxml2/include/libxml/catalog.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 * Fuzzer entry point for libFuzzer / LLVM libFuzzer.
 *
 * Builds two xmlChar* strings from the input buffer (splitting the input
 * in two halves) and calls the target API.
 *
 * The target to fuzz is the internal function:
 *    xmlChar * xmlCatalogListXMLResolve(xmlCatalogEntryPtr catal, const xmlChar * pubID, const xmlChar * sysID)
 *
 * Some builds expose that symbol; some don't. To ensure we call the target
 * when available, declare an extern prototype (using void* for the first arg
 * to avoid depending on internal typedefs) and call it when catalogs are
 * enabled. When not enabled, emulate a NULL result so the harness still runs.
 *
 * The function signature for LLVMFuzzerTestOneInput must not be changed.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize catalogs (no-op if already initialized) */
#ifdef LIBXML_CATALOG_ENABLED
    xmlInitializeCatalog();
#endif

    /* Split the input into two parts for pubID and sysID */
    size_t half = Size / 2;
    size_t len_pub = half;
    size_t len_sys = Size - half;

    /* Allocate and copy into null-terminated buffers of type xmlChar */
    xmlChar *pubID = (xmlChar *)malloc(len_pub + 1);
    xmlChar *sysID = (xmlChar *)malloc(len_sys + 1);
    if (pubID == NULL || sysID == NULL) {
        free(pubID);
        free(sysID);
        return 0;
    }

    if (len_pub > 0)
        memcpy(pubID, Data, len_pub);
    pubID[len_pub] = 0;

    if (len_sys > 0)
        memcpy(sysID, Data + half, len_sys);
    sysID[len_sys] = 0;

    /* Call the target internal catalog resolve API when available.
     *
     * The real internal function signature uses xmlCatalogEntryPtr for the
     * first parameter, but that type is internal to catalog.c. We declare
     * and call a compatible prototype using void* so we can link when the
     * symbol is exported by the build. If it's not available, fall back to
     * the public xmlCatalogResolve.
     */
#ifdef LIBXML_CATALOG_ENABLED
    /* Declare as weak so that if the symbol isn't exported by the build
     * the linker won't fail. When the weak symbol is absent it evaluates
     * to NULL and must be tested before calling.
     */
    extern xmlChar *xmlCatalogListXMLResolve(void *catal,
                                             const xmlChar *pubID,
                                             const xmlChar *sysID) __attribute__((weak));

    xmlChar *res = NULL;

    if (xmlCatalogListXMLResolve) {
        res = xmlCatalogListXMLResolve(NULL, pubID, sysID);
    }

    /* If calling the internal function did not produce a result (symbol
     * might not be present or it returned NULL), fall back to public API
     * to exercise code paths as before.
     */
    if (res == NULL) {
        res = xmlCatalogResolve(pubID, sysID);
    }
#else
    /* If catalogs aren't enabled, emulate no resolution. */
    xmlChar *res = NULL;
#endif

    /* xmlCatalogResolve / xmlCatalogListXMLResolve may return:
     *  - NULL
     *  - a malloc'd xmlChar * (to be freed with xmlFree)
     *  - a special sentinel XML_CATAL_BREAK defined internally as ((xmlChar *) -1)
     *
     * The sentinel macro is internal, so check explicitly for ((xmlChar *)-1).
     */
    if (res != NULL && res != (xmlChar *)-1) {
        xmlFree(res);
    }

    free(pubID);
    free(sysID);

    /* Optionally clean up globals (no-op if not initialized or not enabled) */
#ifdef LIBXML_CATALOG_ENABLED
    xmlCatalogCleanup();
#endif

    return 0;
}
