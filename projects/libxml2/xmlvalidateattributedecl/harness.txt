// Fuzz driver for:
//     int xmlValidateAttributeDecl(xmlValidCtxt * ctxt, xmlDoc * doc, xmlAttribute * attr);
// Fuzzer entry point:
//     int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Project headers (absolute paths discovered in the workspace) */
#include "/src/libxml2/include/libxml/valid.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 Fuzzer entry point that exercises:
   int xmlValidateAttributeDecl(xmlValidCtxt * ctxt, xmlDoc * doc, xmlAttribute * attr);
 The driver builds minimal xmlValidCtxt, xmlDoc and xmlAttribute objects from the
 provided Data buffer and calls the function. Allocated memory is freed before return.
*/

static xmlChar *
dup_string_from_data(const uint8_t *Data, size_t Size, size_t *pos, size_t max_len) {
    if (pos == NULL || *pos >= Size) return NULL;

    /* Consume one byte to determine requested length. Ensure we don't read past Data. */
    uint8_t len_byte = Data[*pos];
    (*pos)++;

    /* Recompute remaining bytes after consuming the length byte. */
    size_t remaining = 0;
    if (*pos <= Size) remaining = Size - *pos;
    else remaining = 0;

    size_t len = (size_t)len_byte;

    /* If requested zero length, make it 1 sometimes (but only if we have bytes left). */
    if (len == 0) {
        if (remaining > 0) len = 1;
        else len = 0;
    }

    /* Cap to available remaining bytes and max_len. */
    if (len > remaining) len = remaining;
    if (len > max_len) len = max_len;

    xmlChar *s = (xmlChar *)malloc(len + 1);
    if (s == NULL) return NULL;

    if (len > 0) {
        memcpy(s, Data + *pos, len);
        *pos += len;
    }
    s[len] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    size_t pos = 0;

    /* Build a minimal xmlDoc */
    xmlDoc doc_s;
    memset(&doc_s, 0, sizeof(doc_s));
    /* Ensure intSubset is NULL to avoid deeper DTD hash lookups in this harness */
    doc_s.intSubset = NULL;

    /* Build a minimal xmlValidCtxt */
    xmlValidCtxt vctxt;
    memset(&vctxt, 0, sizeof(vctxt));
    vctxt.doc = &doc_s;

    /* Build an xmlAttribute and populate fields from Data */
    struct _xmlAttribute attr_s;
    memset(&attr_s, 0, sizeof(attr_s));

    /* Limit lengths to reasonable sizes to avoid excessive allocations */
    const size_t MAX_STR_LEN = 256;

    /* Extract name, elem and defaultValue from Data */
    xmlChar *name = dup_string_from_data(Data, Size, &pos, MAX_STR_LEN);
    xmlChar *elem = dup_string_from_data(Data, Size, &pos, MAX_STR_LEN);
    xmlChar *defaultValue = dup_string_from_data(Data, Size, &pos, MAX_STR_LEN);
    xmlChar *prefix = dup_string_from_data(Data, Size, &pos, MAX_STR_LEN);

    /* Set numeric enum-like fields from next bytes (if available) */
    int atype = 0;
    int def = 0;
    if (pos < Size) {
        atype = Data[pos++] % 10; /* keep within small range */
    }
    if (pos < Size) {
        def = Data[pos++] % 4; /* small range for default type */
    }

    /* Populate the attribute struct */
    attr_s._private = NULL;
    attr_s.type = 0; /* xmlElementType not used by our target function directly */
    attr_s.name = name;
    attr_s.children = NULL;
    attr_s.last = NULL;
    attr_s.parent = NULL;
    attr_s.next = NULL;
    attr_s.prev = NULL;
    attr_s.doc = &doc_s; /* link to doc (safe) */
    attr_s.nexth = NULL;
    attr_s.atype = (xmlAttributeType)atype;
    attr_s.def = (xmlAttributeDefault)def;
    attr_s.defaultValue = defaultValue;
    attr_s.tree = NULL;
    attr_s.prefix = prefix;
    attr_s.elem = elem;

    /* Call the target function */
    /* The function returns int (1 valid, 0 invalid). We ignore the return for this harness. */
    (void) xmlValidateAttributeDecl(&vctxt, &doc_s, &attr_s);

    /* Free allocated memory */
    free(name);
    free(elem);
    free(defaultValue);
    free(prefix);

    return 0;
}
