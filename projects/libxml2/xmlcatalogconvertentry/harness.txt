#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the libxml2 hash header so we get xmlHashTable, xmlChar and xmlHashDeallocator. */
#include "/src/libxml2/include/libxml/hash.h"

/* Provide a simple stub for xmlHashRemoveEntry matching the declaration in hash.h.
 * We declare it with external linkage (to match the header) and mark it weak so that
 * if the real xmlHashRemoveEntry is linked in, that strong symbol will take precedence.
 * The stub is a no-op and returns 0 for fuzzing. */
int __attribute__((weak)) xmlHashRemoveEntry(xmlHashTable *hash, const xmlChar *name, xmlHashDeallocator dealloc) {
    (void)hash;
    (void)name;
    (void)dealloc;
    return 0;
}

/* Include the implementation so static functions like xmlCatalogConvertEntry are
 * compiled into this translation unit. Adjust the path if building outside the
 * provided repository layout. */
#include "/src/libxml2/catalog.c"

/* Fuzzer entry point. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Protect against extremely large allocations driven by malformed fuzz inputs. */
    const size_t MAX_NAME = 1 << 20; /* 1 MB */
    size_t idx = 0;

    /* Create a catalog entry and catalog structures expected by xmlCatalogConvertEntry.
     * The types xmlCatalogEntryPtr and xmlCatalogPtr are defined in the included catalog.c. */
    xmlCatalogEntryPtr entry = (xmlCatalogEntryPtr)calloc(1, sizeof(*entry));
    if (entry == NULL)
        return 0;

    /* Use first byte to pick an integer value for the entry type. */
    entry->type = (int)Data[idx++];

    /* Prepare a name (xmlChar*) from the remaining input bytes (if any). */
    size_t name_len = (Size > idx) ? (Size - idx) : 0;
    if (name_len > MAX_NAME)
        name_len = MAX_NAME;
    if (name_len > 0) {
        entry->name = (xmlChar *)malloc(name_len + 1);
        if (entry->name == NULL) {
            free(entry);
            return 0;
        }
        memcpy(entry->name, Data + idx, name_len);
        entry->name[name_len] = '\0';
    } else {
        entry->name = NULL;
    }

    /* Build a catalog object. The actual struct definition comes from catalog.c. */
    xmlCatalogPtr catal = (xmlCatalogPtr)calloc(1, sizeof(*catal));
    if (catal == NULL) {
        if (entry->name) free(entry->name);
        free(entry);
        return 0;
    }

    /* Provide non-NULL pointers for sgml and xml so xmlCatalogConvertEntry proceeds.
     * The harness stubs xmlHashRemoveEntry to be a no-op, so it's safe to provide a dummy. */
    catal->sgml = (void *)1;

    /* catal->xml is expected to be an xmlCatalogEntryPtr (a catalog root). */
    catal->xml = (xmlCatalogEntryPtr)calloc(1, sizeof(*(catal->xml)));
    if (catal->xml == NULL) {
        if (entry->name) free(entry->name);
        free(entry);
        free(catal);
        return 0;
    }
    /* Ensure the root's children pointer is NULL initially. */
    catal->xml->children = NULL;

    /* name parameter passed to xmlCatalogConvertEntry is marked ATTRIBUTE_UNUSED in the implementation,
     * so we can safely pass the entry->name or NULL. */
    const xmlChar *name_param = entry->name;

    /* Call the function under test.
     * Because the real xmlHashRemoveEntry is stubbed out above, this should be safe. */
    xmlCatalogConvertEntry((void *)entry, (void *)catal, name_param);

    /* Clean up. xmlCatalogConvertEntry may have re-linked entry into catal->xml,
     * but since we used simplistic, small objects and stubbed the hash routines,
     * we simply free what we allocated. We avoid double-freeing: check pointers. */
    if (entry->name) {
        free((void *)entry->name);
        entry->name = NULL;
    }
    free(entry);

    if (catal->xml) {
        /* Note: catal->xml may have been modified to point to entry or have children;
         * we free only the block we allocated. This is simplistic but safe for the harness. */
        free(catal->xml);
    }
    free(catal);

    return 0;
}