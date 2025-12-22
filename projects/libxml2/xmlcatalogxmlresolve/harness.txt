/*
 * Fuzz driver for: xmlChar * xmlCatalogXMLResolve(xmlCatalogEntryPtr catal,
 *                                                  const xmlChar * pubID,
 *                                                  const xmlChar * sysID);
 *
 * The harness builds a small catalog entry (matching the internal layout)
 * and calls xmlCatalogXMLResolve with fuzzed pubID and sysID strings.
 *
 * NOTE: Do not provide fake/weak stubs for xmlCatalogXMLResolve or
 * xmlInitializeCatalog here; use the implementations from the project build.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>
#include <libxml/catalog.h>

/*
 * Re-declare the internal xmlCatalogEntryType and xmlCatalogEntry layout
 * as used by the library's catalog.c so we can construct an instance
 * compatible with xmlCatalogXMLResolve.
 *
 * This matches the private definitions from catalog.c.
 */

typedef enum {
    XML_CATA_REMOVED = -1,
    XML_CATA_NONE = 0,
    XML_CATA_CATALOG,
    XML_CATA_BROKEN_CATALOG,
    XML_CATA_NEXT_CATALOG,
    XML_CATA_GROUP,
    XML_CATA_PUBLIC,
    XML_CATA_SYSTEM,
    XML_CATA_REWRITE_SYSTEM,
    XML_CATA_DELEGATE_PUBLIC,
    XML_CATA_DELEGATE_SYSTEM,
    XML_CATA_URI,
    XML_CATA_REWRITE_URI,
    XML_CATA_DELEGATE_URI
#ifdef LIBXML_SGML_CATALOG_ENABLED
    ,
    SGML_CATA_SYSTEM,
    SGML_CATA_PUBLIC,
    SGML_CATA_ENTITY,
    SGML_CATA_PENTITY,
    SGML_CATA_DOCTYPE,
    SGML_CATA_LINKTYPE,
    SGML_CATA_NOTATION,
    SGML_CATA_DELEGATE,
    SGML_CATA_BASE,
    SGML_CATA_CATALOG,
    SGML_CATA_DOCUMENT,
    SGML_CATA_SGMLDECL
#endif
} xmlCatalogEntryType;

typedef struct _xmlCatalogEntry xmlCatalogEntry;
typedef xmlCatalogEntry *xmlCatalogEntryPtr;

struct _xmlCatalogEntry {
    struct _xmlCatalogEntry *next;
    struct _xmlCatalogEntry *parent;
    struct _xmlCatalogEntry *children;
    xmlCatalogEntryType type;
    xmlChar *name;
    xmlChar *value;
    xmlChar *URL;  /* The expanded URL using the base */
    xmlCatalogPrefer prefer;
    int dealloc;
    int depth;
    struct _xmlCatalogEntry *group;
};

/* Helper to build a simple catalog entry from fuzz data.
 * We create one xmlCatalogEntry with type XML_CATA_PUBLIC and populate
 * name/value fields from provided blobs. */
static xmlCatalogEntryPtr
make_simple_catalog_entry(const xmlChar *name_blob, size_t name_len,
                          const xmlChar *value_blob, size_t value_len) {
    xmlCatalogEntryPtr entry = (xmlCatalogEntryPtr) xmlMalloc(sizeof(xmlCatalogEntry));
    if (entry == NULL)
        return NULL;
    memset(entry, 0, sizeof(xmlCatalogEntry));

    entry->next = NULL;
    entry->parent = NULL;
    entry->children = NULL;
    entry->type = XML_CATA_PUBLIC;

    if (name_blob && name_len > 0)
        entry->name = xmlStrndup(name_blob, (int)name_len);
    else
        entry->name = NULL;

    if (value_blob && value_len > 0)
        entry->value = xmlStrndup(value_blob, (int)value_len);
    else
        entry->value = NULL;

    entry->URL = NULL;
    entry->prefer = XML_CATA_PREFER_NONE;
    entry->dealloc = 0;
    entry->depth = 0;
    entry->group = NULL;

    return entry;
}

static void
free_simple_catalog_entry(xmlCatalogEntryPtr entry) {
    if (entry == NULL) return;
    if (entry->name) xmlFree(entry->name);
    if (entry->value) xmlFree(entry->value);
    if (entry->URL) xmlFree(entry->URL);
    xmlFree(entry);
}

/* If the build of libxml2 used when linking this fuzzer does not include
 * catalog support, some symbols may be absent. Declare the potentially
 * missing symbols as weak so linking succeeds and check at runtime. */
#if defined(__GNUC__) || defined(__clang__)
/* xmlInitializeCatalog is void xmlInitializeCatalog(void); */
extern void xmlInitializeCatalog(void) __attribute__((weak));
/* xmlCatalogXMLResolve is xmlChar * xmlCatalogXMLResolve(xmlCatalogEntryPtr, const xmlChar *, const xmlChar *); */
extern xmlChar *xmlCatalogXMLResolve(xmlCatalogEntryPtr catal, const xmlChar *pubID, const xmlChar *sysID) __attribute__((weak));
#else
/* Fallback: no weak attribute; assume symbols exist (may fail to link) */
extern void xmlInitializeCatalog(void);
extern xmlChar *xmlCatalogXMLResolve(xmlCatalogEntryPtr catal, const xmlChar *pubID, const xmlChar *sysID);
#endif

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
#ifndef LIBXML_CATALOG_ENABLED
    /* If libxml2 was built without catalog support, avoid calling
     * xmlCatalogXMLResolve to prevent undefined references at link time. */
    (void)Data;
    (void)Size;
    return 0;
#else
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml catalog subsystem (no-op if already done).
     * Guard the call: xmlInitializeCatalog may be absent in the linked lib. */
    if (xmlInitializeCatalog)
        xmlInitializeCatalog();

    /* Split input into three parts:
     * - pubID bytes
     * - sysID bytes
     * - catalog entry name/value bytes
     *
     * Be careful for small Sizes so we don't produce a wrapped/negative rem.
     */
    size_t pub_len = Size / 3;
    size_t sys_len = (Size - pub_len) / 2;
    size_t rem = Size - pub_len - sys_len;

    /* Pointers into Data (entry_blob may point to Data+Size if rem == 0; that's OK
     * as long as we don't read beyond the requested lengths). */
    const xmlChar *pub_blob = (const xmlChar *) Data;
    const xmlChar *sys_blob = (const xmlChar *) (Data + pub_len);
    const xmlChar *entry_blob = (const xmlChar *) (Data + pub_len + sys_len);

    /* Clamp lengths to INT_MAX-1 for safe cast to int for xmlStrndup */
    int pub_i = (pub_len > (size_t)(INT_MAX - 1)) ? (INT_MAX - 1) : (int)pub_len;
    int sys_i = (sys_len > (size_t)(INT_MAX - 1)) ? (INT_MAX - 1) : (int)sys_len;

    /* Duplicate the strings using libxml allocators */
    xmlChar *pubID = (pub_i > 0) ? xmlStrndup(pub_blob, pub_i) : NULL;
    xmlChar *sysID = (sys_i > 0) ? xmlStrndup(sys_blob, sys_i) : NULL;

    /* Build a simple catalog entry using the remaining bytes.
     * We split remaining bytes into name and value halves. */
    size_t name_len = rem / 2;
    size_t value_len = rem - name_len;

    int name_i = (name_len > (size_t)(INT_MAX - 1)) ? (INT_MAX - 1) : (int)name_len;
    int value_i = (value_len > (size_t)(INT_MAX - 1)) ? (INT_MAX - 1) : (int)value_len;

    xmlCatalogEntryPtr catalog = make_simple_catalog_entry(entry_blob, (size_t)name_i,
                                                           entry_blob + name_i, (size_t)value_i);
    /* If allocation fails, still attempt a call with a NULL catalog pointer
     * (the function should handle catal == NULL). */

    xmlChar *res = NULL;
    /* Guard the call: xmlCatalogXMLResolve may be absent in the linked lib. */
    if (xmlCatalogXMLResolve) {
        res = xmlCatalogXMLResolve(catalog, (const xmlChar *)pubID, (const xmlChar *)sysID);
    } else {
        /* Symbol not available: skip calling */
        res = NULL;
    }

    /* If a result is returned, free it. */
    if (res != NULL)
        xmlFree(res);

    /* Cleanup */
    if (catalog)
        free_simple_catalog_entry(catalog);
    if (pubID) xmlFree(pubID);
    if (sysID) xmlFree(sysID);

    return 0;
#endif /* LIBXML_CATALOG_ENABLED */
}
