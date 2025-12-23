// Fuzz driver for:
//     xmlChar * xmlCatalogXMLResolveURI(xmlCatalogEntryPtr catal, const xmlChar * URI);
// Fuzzer entry point: LLVMFuzzerTestOneInput

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Enable catalog code path when including the source.
#ifndef LIBXML_CATALOG_ENABLED
#define LIBXML_CATALOG_ENABLED
#endif

// Include the target source to access the static/internal function.
// Adjust the path if necessary for your build environment.
#include "/src/libxml2/catalog.c"

// Fuzzer entry point
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Make a mutable, null-terminated copy of the input for use as URIs/names.
    // xmlNewCatalogEntry duplicates the strings passed to it, so it's OK to
    // free this buffer later.
    char *buf = malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Use first byte to decide how many catalog entries to create (0..5).
    // Keep the number small to avoid deep recursion/large allocations.
    size_t idx = 0;
    unsigned nEntries = (unsigned)((unsigned char)buf[idx]) % 6;
    idx++;

    // If there is no remaining data to use as URI content, provide an empty string.
    const char *remaining = (idx < Size) ? (buf + idx) : "";
    size_t remaining_len = (idx < Size) ? (Size - idx) : 0;

    // Clamp number of entries so we don't slice beyond the buffer.
    if (remaining_len == 0) {
        nEntries = 0;
    } else if ((size_t)nEntries > remaining_len) {
        nEntries = (unsigned)remaining_len;
    }

    // Helper: create one catalog entry with value pointing into our buffer.
    // We'll create a simple linked list of xmlCatalogEntryPtr nodes.
    xmlCatalogEntryPtr head = NULL;
    xmlCatalogEntryPtr tail = NULL;

    // Split the remaining buffer roughly evenly among the entries for names/values.
    size_t per = (nEntries > 0) ? (remaining_len / nEntries) : 0;
    // Given we've clamped nEntries <= remaining_len, per >= 1 when nEntries > 0.

    size_t off = 0;
    for (unsigned i = 0; i < nEntries; i++) {
        const xmlChar *name = NULL;
        const xmlChar *value = NULL;

        if (remaining_len > 0) {
            // choose slice for this entry
            size_t slice_len = per;
            if (i == nEntries - 1) {
                // last one takes the rest
                slice_len = remaining_len - off;
            }
            // Create a transient null-terminated string for this slice
            // We'll allocate a tiny buffer so xmlNewCatalogEntry duplicates it
            // and we can free it immediately.
            char *tmp = NULL;
            if (slice_len > 0) {
                tmp = (char *)malloc(slice_len + 1);
                if (tmp == NULL) break;
                memcpy(tmp, remaining + off, slice_len);
                tmp[slice_len] = '\0';
                name = (const xmlChar *)tmp;
                value = (const xmlChar *)tmp;
            } else {
                // empty string
                tmp = (char *)malloc(1);
                if (tmp == NULL) break;
                tmp[0] = '\0';
                name = (const xmlChar *)tmp;
                value = (const xmlChar *)tmp;
            }

            off += slice_len;
            // Create a catalog entry of type XML_CATA_URI (URI entry)
            xmlCatalogEntryPtr node = xmlNewCatalogEntry(XML_CATA_URI,
                                                         name, value,
                                                         NULL,
                                                         xmlCatalogDefaultPrefer,
                                                         NULL);
            // tmp was duplicated by xmlNewCatalogEntry (xmlStrdup), free our tmp
            free(tmp);

            if (node == NULL) {
                // allocation failure; break out and cleanup later
                break;
            }

            // append to list
            if (head == NULL) {
                head = tail = node;
            } else {
                tail->next = node;
                node->parent = NULL;
                tail = node;
            }
        } else {
            // No data left to populate entries, create an entry with NULL values.
            xmlCatalogEntryPtr node = xmlNewCatalogEntry(XML_CATA_URI,
                                                         NULL, NULL,
                                                         NULL,
                                                         xmlCatalogDefaultPrefer,
                                                         NULL);
            if (node == NULL) break;
            if (head == NULL) {
                head = tail = node;
            } else {
                tail->next = node;
                node->parent = NULL;
                tail = node;
            }
        }
    }

    // Now call the target function with the constructed list and the full remaining input as URI.
    const xmlChar *uri = (const xmlChar *)remaining;
    xmlChar *res = NULL;

    // The function is static/internal; by including catalog.c above we can call it directly.
    // It will handle NULL input for catal or uri as appropriate.
    res = xmlCatalogXMLResolveURI(head, uri);

    // Free result if non-NULL
    if (res != NULL) {
        xmlFree(res);
    }

    // Clean up the catalog entries we created.
    if (head != NULL) {
        xmlFreeCatalogEntryList(head);
    }

    // Free the input buffer
    free(buf);

    return 0;
}
