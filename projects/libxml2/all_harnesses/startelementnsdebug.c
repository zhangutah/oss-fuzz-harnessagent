#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <libxml/tree.h>

/*
 This harness uses the real startElementNsDebug from the project's xmllint.c.
 xmllint.c originally marks the function static; to allow the harness to call it
 we temporarily make 'static' empty while including the source.
*/

#define static /* remove static so functions become externally visible */
// Insert a weak stub for xmllintShell to satisfy linkers that expect it.
// Make it weak so if the real implementation is linked in, it will be used instead.
#ifdef __cplusplus
extern "C" {
#endif
void xmllintShell(xmlDoc *doc, const char *filename, FILE * output) __attribute__((weak));
void xmllintShell(xmlDoc *doc, const char *filename, FILE * output) {
    (void)doc;
    (void)filename;
    (void)output;
    /* no-op fallback */
}
#ifdef __cplusplus
}
#endif

#include "../xmllint.c"
#undef static

/* Helper: safe allocate a null-terminated xmlChar string using bytes from Data.
   - offset is updated.
   - maxlen bounds the maximum allocated string length to avoid huge allocations.
   Returns pointer into newly malloc'd memory (should be freed by caller). */
static xmlChar *consume_string(const uint8_t *Data, size_t Size, size_t *offset, size_t maxlen) {
    if (*offset >= Size) {
        xmlChar *s = (xmlChar *)malloc(1);
        if (s) s[0] = '\0';
        return s;
    }
    /* Read a length byte (if available) */
    uint8_t len_byte = Data[*offset];
    (*offset)++;
    size_t len = (size_t)(len_byte) % (maxlen + 1); /* 0..maxlen */

    /* Copy up to len bytes or however many remain */
    size_t remaining = (Size > *offset) ? (Size - *offset) : 0;
    size_t to_copy = (len <= remaining) ? len : remaining;

    xmlChar *s = (xmlChar *)malloc(to_copy + 1);
    if (!s) return NULL;
    if (to_copy > 0)
        memcpy(s, Data + *offset, to_copy);
    s[to_copy] = '\0';

    *offset += to_copy;
    return s;
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    size_t offset = 0;

    /* Small bounds to keep allocations reasonable and avoid OOM */
    const int MAX_NS = 4;
    const int MAX_ATTR = 4;
    const size_t MAX_NAME_LEN = 64;
    const size_t MAX_VALUE_LEN = 256;

    /* Derive small counts from input bytes (if available) */
    int nb_namespaces = 0;
    int nb_attributes = 0;
    int nb_defaulted = 0;

    if (offset < Size) {
        nb_namespaces = Data[offset] % (MAX_NS + 1); /* 0..MAX_NS */
        offset++;
    }
    if (offset < Size) {
        nb_attributes = Data[offset] % (MAX_ATTR + 1); /* 0..MAX_ATTR */
        offset++;
    }
    if (offset < Size) {
        nb_defaulted = Data[offset] & 1;
        offset++;
    }

    /* Build localname, prefix, URI */
    xmlChar *localname = consume_string(Data, Size, &offset, MAX_NAME_LEN);
    xmlChar *prefix = consume_string(Data, Size, &offset, MAX_NAME_LEN);
    xmlChar *URI = consume_string(Data, Size, &offset, MAX_NAME_LEN);

    /* Build namespaces array (nb_namespaces * 2 entries) */
    const xmlChar **namespaces = NULL;
    xmlChar **ns_storage = NULL; /* to free strings later */
    if (nb_namespaces > 0) {
        int entries = nb_namespaces * 2;
        namespaces = (const xmlChar **)malloc(sizeof(xmlChar *) * entries);
        ns_storage = (xmlChar **)malloc(sizeof(xmlChar *) * entries);
        if (namespaces == NULL || ns_storage == NULL) {
            /* allocation failure: clean up and exit early */
            free(localname); free(prefix); free(URI);
            free(namespaces); free(ns_storage);
            return 0;
        }
        for (int i = 0; i < entries; i++) {
            ns_storage[i] = consume_string(Data, Size, &offset, MAX_NAME_LEN);
            namespaces[i] = ns_storage[i];
        }
    }

    /* Build attributes array (nb_attributes * 5 entries). For each attribute we create:
       [localname, prefix (or NULL), URI (or NULL), value_start, value_end] */
    const xmlChar **attributes = NULL;
    xmlChar **attr_storage = NULL; /* storage for strings used by attributes */
    if (nb_attributes > 0) {
        int entries = nb_attributes * 5;
        attributes = (const xmlChar **)malloc(sizeof(xmlChar *) * entries);
        /* We'll store up to 4 strings per attribute (local, prefix, URI, value),
           but to simplify free logic we store pointers for each slot. */
        attr_storage = (xmlChar **)malloc(sizeof(xmlChar *) * (nb_attributes * 4));
        if (attributes == NULL || attr_storage == NULL) {
            free(localname); free(prefix); free(URI);
            free(namespaces); free(ns_storage);
            free(attributes); free(attr_storage);
            return 0;
        }
        for (int a = 0; a < nb_attributes; a++) {
            int base_attr = a * 5;
            /* local name */
            attr_storage[a * 4 + 0] = consume_string(Data, Size, &offset, MAX_NAME_LEN);
            attributes[base_attr + 0] = attr_storage[a * 4 + 0];
            /* prefix - allow NULL half the time (if no data or based on next byte) */
            if (offset < Size && (Data[offset] & 1)) {
                attr_storage[a * 4 + 1] = consume_string(Data, Size, &offset, MAX_NAME_LEN);
                attributes[base_attr + 1] = attr_storage[a * 4 + 1];
            } else {
                attr_storage[a * 4 + 1] = NULL;
                attributes[base_attr + 1] = NULL;
            }
            /* URI - allow NULL or a string */
            if (offset < Size && (Data[offset] & 1)) {
                attr_storage[a * 4 + 2] = consume_string(Data, Size, &offset, MAX_NAME_LEN);
                attributes[base_attr + 2] = attr_storage[a * 4 + 2];
            } else {
                attr_storage[a * 4 + 2] = NULL;
                attributes[base_attr + 2] = NULL;
            }
            /* value: allocate a value buffer and set start and end pointers */
            size_t want_val_len = 0;
            if (offset < Size) {
                /* derive a length from a single byte but cap it */
                want_val_len = (size_t)(Data[offset] % (MAX_VALUE_LEN + 1));
                offset++;
            }
            /* copy up to want_val_len bytes from Data */
            size_t remaining = (Size > offset) ? (Size - offset) : 0;
            size_t to_copy = (want_val_len <= remaining) ? want_val_len : remaining;
            xmlChar *valbuf = (xmlChar *)malloc(to_copy + 1 + 1); /* +1 for null, +1 extra safe */
            if (!valbuf) {
                /* On allocation failure set value pointers to NULL/zero */
                attr_storage[a * 4 + 3] = NULL;
                attributes[base_attr + 3] = NULL;
                attributes[base_attr + 4] = NULL;
            } else {
                if (to_copy > 0)
                    memcpy(valbuf, Data + offset, to_copy);
                valbuf[to_copy] = '\0';
                /* store pointers: start and end (end points to one past last char) */
                attr_storage[a * 4 + 3] = valbuf;
                attributes[base_attr + 3] = attr_storage[a * 4 + 3];
                attributes[base_attr + 4] = attr_storage[a * 4 + 3] + (ptrdiff_t)to_copy;
                offset += to_copy;
            }
        }
    }

    /* Prepare a minimal xmllintState and call the function */
    xmllintState state;
    /* Initialize the fields used by startElementNsDebug */
    /* NOTE: We're only using callbacks and noout in startElementNsDebug. */
    memset(&state, 0, sizeof(state));

    /* derive noout from a byte if available */
    if (Size > 0) {
        state.noout = (Data[0] & 0x80) ? 1 : 0; /* arbitrary */
    }

    /* Call the target function (the real one included from xmllint.c) */
    startElementNsDebug(&state,
                        localname ? localname : (const xmlChar *)"",
                        prefix ? prefix : (const xmlChar *)"",
                        URI ? URI : (const xmlChar *)"",
                        nb_namespaces,
                        namespaces,
                        nb_attributes,
                        nb_defaulted,
                        attributes);

    /* Cleanup allocated memory */
    free(localname);
    free(prefix);
    free(URI);

    if (ns_storage) {
        int ns_entries = nb_namespaces * 2;
        for (int i = 0; i < ns_entries; i++) {
            free(ns_storage[i]);
        }
        free(ns_storage);
    }
    free(namespaces);

    if (attr_storage) {
        for (int a = 0; a < nb_attributes; a++) {
            /* free local, prefix, URI, value */
            xmlChar *p0 = attr_storage[a * 4 + 0];
            xmlChar *p1 = attr_storage[a * 4 + 1];
            xmlChar *p2 = attr_storage[a * 4 + 2];
            xmlChar *p3 = attr_storage[a * 4 + 3];
            if (p0) free(p0);
            if (p1) free(p1);
            if (p2) free(p2);
            if (p3) free(p3);
        }
        free(attr_storage);
    }
    free(attributes);

    return 0;
}
