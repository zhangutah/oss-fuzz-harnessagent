#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>

/*
 * Make sure the relaxng.c code is compiled into this translation unit so we
 * can call the file-static xmlRelaxNGAttributeMatch function directly.
 *
 * The harness lives in fuzz/, relaxng.c is in the parent directory of fuzz/.
 */
#define LIBXML_RELAXNG_ENABLED
#define IN_LIBXML
#include "../relaxng.c"

/* ===== Helpers to build test structures from the input bytes =====
 *
 * We interpret the fuzzer data as a compact description of:
 *  - a small linked set of xmlRelaxNGDefine nodes (with limited depth),
 *  - an xmlAttr with optional ns and name strings.
 *
 * Layout used (consumed sequentially from Data pointer):
 *  - One control byte per created define node describing which fields are present.
 *    Bit layout in control byte:
 *      bit 0 (1): has_name
 *      bit 1 (2): has_ns
 *      bit 2 (4): has_nameClass
 *      bit 3 (8): has_content
 *      bit 4 (16): has_next
 *    After control byte, if a field is present, we read a length byte L and then L bytes
 *    as the string content (for name/ns fields) or proceed recursively for sub-nodes.
 *
 *  - After building the top-level define, we build a prop attribute:
 *    One control byte:
 *      bit 0 (1): prop has name (if 0 -> name == NULL)
 *      bit 1 (2): prop has ns (if 1 -> allocate ns and read href string)
 *    For name/ns strings, read length byte L and then L bytes for content.
 *
 * We cap recursion depth and total allocations to avoid excessive work.
 */

#define MAX_RECURSION_DEPTH 6
#define MAX_ALLOCS 1024

struct alloc_tracker {
    void *list[MAX_ALLOCS];
    size_t count;
};
static void track_alloc(struct alloc_tracker *t, void *p) {
    if (t->count < MAX_ALLOCS) t->list[t->count++] = p;
}
static void free_tracked(struct alloc_tracker *t) {
    for (size_t i = 0; i < t->count; ++i) free(t->list[i]);
    t->count = 0;
}

/* Safely read one byte, return -1 if none left */
static int
read_byte(const uint8_t **p, size_t *len) {
    if (*len == 0) return -1;
    int v = **p;
    (*p)++;
    (*len)--;
    return v;
}

/* Read a small string: one length byte followed by that many bytes.
 * Always NUL-terminate and allocate memory. If there's not enough data,
 * allocate an empty string. */
static xmlChar *
read_string(const uint8_t **p, size_t *len, struct alloc_tracker *t) {
    int lb = read_byte(p, len);
    if (lb < 0) {
        // No length byte available; return NULL to represent absence
        return NULL;
    }
    size_t L = (size_t)lb;
    if (L > *len) L = *len;
    xmlChar *s = (xmlChar *)malloc(L + 1);
    if (s == NULL) return NULL;
    track_alloc(t, s);
    if (L > 0) {
        memcpy(s, *p, L);
        *p += L;
        *len -= L;
    }
    s[L] = '\0';
    return s;
}

/* Recursively build a define node according to the compact format above
 * using the real xmlRelaxNGDefine structure from relaxng.c */
static xmlRelaxNGDefinePtr
build_define(const uint8_t **p, size_t *len, int depth, struct alloc_tracker *t) {
    if (depth > MAX_RECURSION_DEPTH) return NULL;
    int ctrl = read_byte(p, len);
    if (ctrl < 0) return NULL;

    xmlRelaxNGDefinePtr node = (xmlRelaxNGDefinePtr)malloc(sizeof(xmlRelaxNGDefine));
    if (!node) return NULL;
    track_alloc(t, node);

    /* Initialize many fields conservatively (relaxng.c define is larger) */
    memset(node, 0, sizeof(xmlRelaxNGDefine));

    if (ctrl & 1) { /* has_name */
        node->name = read_string(p, len, t);
    } else {
        node->name = NULL;
    }
    if (ctrl & 2) { /* has_ns */
        node->ns = read_string(p, len, t);
    } else {
        node->ns = NULL;
    }

    /* For type, read a byte if available; else default 0.
     * Map to known constants: 1 -> EXCEPT, 2 -> CHOICE, else other (0). */
    int tbyte = read_byte(p, len);
    if (tbyte < 0) tbyte = 0;
    if ((tbyte & 3) == 1) node->type = XML_RELAXNG_EXCEPT;
    else if ((tbyte & 3) == 2) node->type = XML_RELAXNG_CHOICE;
    else node->type = 0;

    if (ctrl & 4) { /* nameClass */
        node->nameClass = build_define(p, len, depth + 1, t);
    } else {
        node->nameClass = NULL;
    }
    if (ctrl & 8) { /* content */
        node->content = build_define(p, len, depth + 1, t);
    } else {
        node->content = NULL;
    }
    if (ctrl & 16) { /* next */
        node->next = build_define(p, len, depth + 1, t);
    } else {
        node->next = NULL;
    }
    return node;
}

/* Build attribute (prop) using real xmlAttr and xmlNs structures */
static xmlAttrPtr
build_prop(const uint8_t **p, size_t *len, struct alloc_tracker *t) {
    int ctrl = read_byte(p, len);
    if (ctrl < 0) {
        // No control byte: return attribute with NULL fields
        xmlAttrPtr a = (xmlAttrPtr)calloc(1, sizeof(xmlAttr));
        if (a) { track_alloc(t, a); a->name = NULL; a->ns = NULL; }
        return a;
    }
    xmlAttrPtr a = (xmlAttrPtr)calloc(1, sizeof(xmlAttr));
    if (!a) return NULL;
    track_alloc(t, a);

    if (ctrl & 1) {
        a->name = read_string(p, len, t);
    } else {
        a->name = NULL;
    }
    if (ctrl & 2) {
        xmlNsPtr ns = (xmlNsPtr)malloc(sizeof(xmlNs));
        if (!ns) { a->ns = NULL; return a; }
        track_alloc(t, ns);
        ns->href = read_string(p, len, t);
        a->ns = ns;
    } else {
        a->ns = NULL;
    }
    return a;
}

/* The fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    const uint8_t *p = Data;
    size_t len = Size;

    struct alloc_tracker tr;
    tr.count = 0;

    /* Build top-level define */
    xmlRelaxNGDefinePtr top = build_define(&p, &len, 0, &tr);

    /* Build prop */
    xmlAttrPtr prop = build_prop(&p, &len, &tr);

    /* Call the real function from included relaxng.c. The function
     * signature matches:
     *   static int xmlRelaxNGAttributeMatch(xmlRelaxNGValidCtxtPtr ctxt,
     *                                       xmlRelaxNGDefinePtr define,
     *                                       xmlAttrPtr prop);
     *
     * Because we included relaxng.c into this translation unit, the static
     * function is available here and will be invoked directly.
     *
     * We pass a NULL context pointer; the function can handle it in practice
     * (it doesn't use the ctxt pointer in the attribute matching logic).
     */
    (void)xmlRelaxNGAttributeMatch(NULL, top, prop);

    /* Free all allocations tracked */
    free_tracked(&tr);

    return 0;
}
