#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Prefer absolute project headers as requested.
 * These headers declare xmlAddAttributeDecl and the involved types.
 */
#include "/src/libxml2/include/libxml/valid.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/parser.h"

/*
 * Fuzzer entry point.
 *
 * This driver crafts plausible arguments for:
 * xmlAttribute * xmlAddAttributeDecl(xmlValidCtxt * ctxt,
 *                                    xmlDtd * dtd,
 *                                    const xmlChar * elem,
 *                                    const xmlChar * name,
 *                                    const xmlChar * ns,
 *                                    xmlAttributeType type,
 *                                    xmlAttributeDefault def,
 *                                    const xmlChar * defaultValue,
 *                                    xmlEnumeration * tree);
 *
 * Strategy:
 * - Split the input bytes into several small strings (elem, name, ns, defaultValue).
 * - Choose enum values for type and def based on input bytes.
 * - Optionally build a short xmlEnumeration linked list if input supplies data.
 * - Create a minimal xmlDtd (doc = NULL) so the function avoids complex branches
 *   that require a full xmlDoc, while still exercising many code paths.
 *
 * Note: This harness intentionally leaked a small amount of memory per invocation
 * in an earlier version. That caused out-of-memory over many fuzz iterations.
 * The current version frees the DTD and the strings created in this harness
 * after the call to avoid accumulating memory across runs.
 */

static size_t clamp_len(size_t v, size_t max) {
    return (v > max) ? max : v;
}

/* Safely create a NUL-terminated xmlChar* from a data slice */
static xmlChar *make_xmlstring_from(const uint8_t *data, size_t len) {
    if (len == 0) return NULL;
    /* xmlStrndup is provided by libxml2 and allocates with xmlMalloc */
    return xmlStrndup((const xmlChar *)data, (int)len);
}

/* Build an xmlEnumeration linked list from the provided buffer.
 * Format:
 *   first byte: count (0..max_count)
 *   for each entry:
 *     one byte: entry_length (0..max_entry_len)
 *     next entry_length bytes: entry data
 *
 * Returns pointer to head or NULL if none.
 *
 * This function will not free anything; memory is allocated using xmlMalloc/xmlStrdup
 * to be compatible with libxml2 freeing conventions.
 */
static xmlEnumeration *build_enumeration(const uint8_t *data, size_t size, size_t *consumed_out) {
    size_t pos = 0;
    const size_t MAX_COUNT = 8;
    const size_t MAX_ENTRY_LEN = 64;

    if (size == 0) {
        if (consumed_out) *consumed_out = 0;
        return NULL;
    }

    unsigned count = data[pos++] % (MAX_COUNT + 1); /* 0..MAX_COUNT */
    xmlEnumeration *head = NULL;
    xmlEnumeration *last = NULL;

    for (unsigned i = 0; i < count; i++) {
        if (pos >= size) break;
        size_t entry_len = data[pos++] % (MAX_ENTRY_LEN + 1); /* 0..MAX_ENTRY_LEN */
        if (entry_len == 0) {
            /* skip empty entries but still create node with NULL name */
            xmlEnumeration *node = (xmlEnumeration *)xmlMalloc(sizeof(xmlEnumeration));
            if (node == NULL) break;
            node->name = NULL;
            node->next = NULL;
            if (last) last->next = node; else head = node;
            last = node;
            continue;
        }
        if (pos + entry_len > size) {
            /* not enough bytes left */
            entry_len = size - pos;
        }
        xmlChar *s = make_xmlstring_from(data + pos, entry_len);
        pos += entry_len;
        xmlEnumeration *node = (xmlEnumeration *)xmlMalloc(sizeof(xmlEnumeration));
        if (node == NULL) {
            if (s) xmlFree(s);
            break;
        }
        node->name = (const xmlChar *)s;
        node->next = NULL;
        if (last) last->next = node; else head = node;
        last = node;
    }

    if (consumed_out) *consumed_out = pos;
    return head;
}

/* Helper to read a length byte and clamp (C version, since lambdas are C++ only) */
static size_t read_len_c(const uint8_t *Data, size_t Size, size_t *pos, size_t default_max) {
    if (*pos >= Size) return 0;
    unsigned v = Data[(*pos)++];
    return clamp_len((size_t)(v), default_max);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /*
     * Initialize libxml parser subsystem (no-op if already initialized).
     * This is safe to call repeatedly.
     */
    xmlInitParser();

    size_t pos = 0;

    /* Read small lengths for the strings (keep them short to avoid huge allocations) */
    const size_t MAX_STR = 128;

    /* Get lengths using the C helper */
    size_t elem_len = read_len_c(Data, Size, &pos, 32);
    size_t name_len = read_len_c(Data, Size, &pos, 32);
    size_t ns_len = read_len_c(Data, Size, &pos, 16);
    size_t defval_len = read_len_c(Data, Size, &pos, 64);

    /* Ensure we do not read past buffer for string contents */
    if (pos + elem_len + name_len + ns_len + defval_len > Size) {
        /* adjust lengths proportionally */
        size_t remaining = (Size > pos) ? (Size - pos) : 0;
        /* cap each to what's remaining */
        if (remaining == 0) {
            elem_len = name_len = ns_len = defval_len = 0;
        } else {
            size_t each = remaining / 4;
            elem_len = clamp_len(elem_len, each);
            name_len = clamp_len(name_len, each);
            ns_len = clamp_len(ns_len, each);
            defval_len = clamp_len(defval_len, remaining - (elem_len + name_len + ns_len));
        }
    }

    /* Create strings from slices */
    xmlChar *elem = NULL;
    xmlChar *name = NULL;
    xmlChar *ns = NULL;
    xmlChar *defaultValue = NULL;

    if (elem_len > 0 && pos + elem_len <= Size) {
        elem = make_xmlstring_from(Data + pos, elem_len);
        pos += elem_len;
    }
    if (name_len > 0 && pos + name_len <= Size) {
        name = make_xmlstring_from(Data + pos, name_len);
        pos += name_len;
    }
    if (ns_len > 0 && pos + ns_len <= Size) {
        ns = make_xmlstring_from(Data + pos, ns_len);
        pos += ns_len;
    }
    if (defval_len > 0 && pos + defval_len <= Size) {
        defaultValue = make_xmlstring_from(Data + pos, defval_len);
        pos += defval_len;
    }

    /* Minimum required fields: name and elem. The real function returns early if they are NULL.
     * Keep possibility of NULL to exercise those branches as well.
     */

    /* Determine type and def enums if available */
    xmlAttributeType type = XML_ATTRIBUTE_CDATA;
    xmlAttributeDefault def = XML_ATTRIBUTE_NONE;

    if (pos < Size) {
        unsigned v = Data[pos++];
        /* xmlAttributeType enum values in tree.h start at 1, with count = 9 entries */
        const unsigned TYPE_COUNT = 9;
        type = (xmlAttributeType)(1 + (v % TYPE_COUNT));
    }

    if (pos < Size) {
        unsigned v = Data[pos++];
        /* xmlAttributeDefault enum values in tree.h are 1..4 */
        const unsigned DEF_COUNT = 4;
        def = (xmlAttributeDefault)(1 + (v % DEF_COUNT));
    }

    /* Optionally build an enumeration list from the remaining bytes */
    size_t consumed_enum = 0;
    xmlEnumeration *tree = NULL;
    if (pos < Size) {
        tree = build_enumeration(Data + pos, Size - pos, &consumed_enum);
        pos += consumed_enum;
    }

    /*
     * Build a minimal xmlDtd. To avoid heavy dependencies, set doc = NULL.
     * This keeps xmlAddAttributeDecl in simpler code paths but still valid.
     */
    xmlDtd *dtd = (xmlDtd *)xmlMalloc(sizeof(xmlDtd));
    if (dtd == NULL) {
        /* Allocation failed, free any allocated strings and return. */
        if (elem) xmlFree(elem);
        if (name) xmlFree(name);
        if (ns) xmlFree(ns);
        if (defaultValue) xmlFree(defaultValue);
        /* xmlEnumeration nodes and their names are allocated with xmlMalloc/xmlStrdup.
         * xmlAddAttributeDecl will free or take ownership as appropriate; since we
         * could not allocate the DTD to call it, free the enumeration here.
         */
        if (tree) xmlFreeEnumeration(tree);
        return 0;
    }
    /* Zero-init the dtd to reduce chances of touching invalid pointers in xmlAddAttributeDecl */
    memset(dtd, 0, sizeof(xmlDtd));
    dtd->doc = NULL;

    /* Build a minimal validation context as NULL or zeroed structure; pass NULL to exercise that path too.
     * We will pass NULL here to exercise branches where ctxt is NULL.
     */
    xmlValidCtxt *ctxt = NULL;

    /* Call the target function */
    xmlAttribute *attr = NULL;
    attr = xmlAddAttributeDecl(ctxt, dtd, (const xmlChar *)elem, (const xmlChar *)name,
                               (const xmlChar *)ns, type, def, (const xmlChar *)defaultValue, tree);

    /*
     * Free what this harness allocated and free the dtd so any structures
     * allocated and attached by xmlAddAttributeDecl are reclaimed.
     *
     * Note:
     * - xmlAddAttributeDecl either frees the enumeration on failure or attaches it
     *   to the returned attribute. In the latter case xmlFreeDtd(dtd) will free it.
     * - xmlAddAttributeDecl duplicates or looks-up the passed strings; our original
     *   xmlChar* pointers are owned by this harness and must be freed here.
     *
     * Do not access 'attr' after calling xmlFreeDtd because freeing the DTD will
     * free the attribute returned on success; accessing it after free would be UB.
     */
    if (elem) xmlFree(elem);
    if (name) xmlFree(name);
    if (ns) xmlFree(ns);
    if (defaultValue) xmlFree(defaultValue);

    /* Free the DTD to avoid accumulating memory across fuzzing iterations. */
    xmlFreeDtd(dtd);

    /* The harness returns 0 to indicate the input was processed. */
    (void)attr;  /* silence unused warning if any */
    return 0;
}
