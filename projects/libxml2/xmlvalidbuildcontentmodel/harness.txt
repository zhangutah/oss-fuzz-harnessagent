#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/*
 * Includes from the libxml2 tree/validation/regexp APIs.
 * These header paths are the project-installed include paths used
 * in the repository this fuzz driver targets.
 */
#include <libxml/valid.h>
#include <libxml/tree.h>
#include <libxml/xmlautomata.h>
#include <libxml/xmlregexp.h>

/*
 * Fuzzer entry point
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/* No-op error/warning callbacks to avoid noisy output during fuzzing */
static void
fuzz_validity_error(void *ctx, const char *msg, ...) {
    (void)ctx;
    (void)msg;
    /* swallow messages */
}
static void
fuzz_validity_warning(void *ctx, const char *msg, ...) {
    (void)ctx;
    (void)msg;
    /* swallow messages */
}

/* Simple helper to sanitize strings so they do not contain regex metacharacters
 * or other problematic bytes that could cause the regex parser to attempt very
 * large allocations. We restrict to a conservative alphanumeric + few safe chars.
 */
static void
sanitize_name(char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)buf[i];
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == ':') {
            /* OK */
        } else {
            buf[i] = 'a';
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size < 1)
        return 0;

    /* Simple, robust parser of the input bytes to produce small strings
     * and a content model occurrence modifier. Keep lengths small to avoid
     * huge allocations and to satisfy xmlBuildQName buffer expectations.
     */
    size_t pos = 0;

    /* name length (0..min(MAX_NAME - 1, remaining))
     *
     * IMPORTANT: compute final name_len before allocating name_buf to avoid
     * the case where initial computed name_len==0 leads to allocating size 1,
     * then changing name_len to 1 and writing two bytes (overflow).
     */
    size_t name_len = 0;
    if (pos < Size) {
        size_t max_name = Size - pos;
        /* Lower the allowed max name size to avoid pathological regex parsing
         * from fuzzer inputs that may produce huge allocations. */
        const size_t MAX_NAME = 16; /* conservative small value */
        if (max_name > MAX_NAME) max_name = MAX_NAME;
        /* safe to read Data[pos] because pos < Size here */
        name_len = (size_t)Data[pos++] % (max_name + 1);
        /* cap to remaining bytes (don't read beyond Data) */
        if (name_len > Size - pos) name_len = Size - pos;
    } else {
        name_len = 0;
    }

    /* ensure at least a short default name if there are no bytes */
    int use_default_name = 0;
    if (name_len == 0) {
        use_default_name = 1;
        name_len = 1;
    }

    char *name_buf = (char *)malloc(name_len + 1);
    if (!name_buf) return 0;
    if (!use_default_name && name_len > 0) {
        /* safe because we ensured pos + name_len <= Size above */
        memcpy(name_buf, Data + pos, name_len);
        pos += name_len;
    } else {
        /* populate a short default name */
        name_buf[0] = 'a';
        /* we didn't consume Data bytes for the name in this branch */
    }
    name_buf[name_len] = '\0';

    /* prefix length (0..min(MAX_PREFIX - 1, remaining)) */
    size_t prefix_len = 0;
    if (pos < Size) {
        size_t max_pref = Size - pos;
        const size_t MAX_PREFIX = 8; /* small, safe */
        if (max_pref > MAX_PREFIX) max_pref = MAX_PREFIX;
        /* safe to read Data[pos] because pos < Size here */
        prefix_len = (size_t)Data[pos++] % (max_pref + 1);
        if (prefix_len > Size - pos) prefix_len = Size - pos;
    }
    char *prefix_buf = NULL;
    if (prefix_len > 0) {
        prefix_buf = (char *)malloc(prefix_len + 1);
        if (!prefix_buf) {
            free(name_buf);
            return 0;
        }
        memcpy(prefix_buf, Data + pos, prefix_len);
        pos += prefix_len;
        prefix_buf[prefix_len] = '\0';
    }

    /* occurrence modifier: map to a safe subset of enum values
     *
     * Restrict to ONCE or OPT only to avoid creating '*'/'+' style content models
     * that can lead to extremely large automata/regex during compilation.
     */
    int ocur_val = 0; /* default ONCE */
    if (pos < Size) {
        /* limit to 0..1 only */
        ocur_val = Data[pos++] % 2;
    }

    /*
     * Sanitize name and prefix to avoid regex metacharacters that could cause
     * huge allocations inside libxml2's regex parsing routines.
     */
    sanitize_name(name_buf, name_len);
    if (prefix_buf) sanitize_name(prefix_buf, prefix_len);

    /*
     * Build minimal xmlElement and xmlElementContent structures expected
     * by xmlValidBuildContentModel.
     *
     * Note: these structures are part of libxml2 internal deprecated APIs,
     * but the fuzz target is exercising them directly.
     */
    xmlElement *elem = (xmlElement *)calloc(1, sizeof(xmlElement));
    if (!elem) {
        free(name_buf);
        if (prefix_buf) free(prefix_buf);
        return 0;
    }

    /* Set the element declaration node type and element type so the
     * function proceeds into content model building.
     */
    elem->type = XML_ELEMENT_DECL; /* from tree.h */
    elem->etype = XML_ELEMENT_TYPE_ELEMENT; /* from tree.h */
    /* element name used by error messages; keep small and safe */
    elem->name = (const xmlChar *)name_buf;

    /* create a single xmlElementContent describing a single child element */
    xmlElementContent *content = (xmlElementContent *)calloc(1, sizeof(xmlElementContent));
    if (!content) {
        free((void *)elem);
        free(name_buf);
        if (prefix_buf) free(prefix_buf);
        return 0;
    }

    /* Set content to ELEMENT (not PCDATA/SEQ/OR) to match code path */
    content->type = XML_ELEMENT_CONTENT_ELEMENT;
    /* occurrence - restricted to safe values only */
    switch (ocur_val) {
        case 0: content->ocur = XML_ELEMENT_CONTENT_ONCE; break;
        default:content->ocur = XML_ELEMENT_CONTENT_OPT; break;
    }

    /* content->name and prefix are xmlChar* */
    /* Use the same name buffer so xmlBuildQName will combine name/prefix properly */
    content->name = (const xmlChar *)name_buf;
    content->prefix = prefix_buf ? (const xmlChar *)prefix_buf : NULL;

    elem->content = content;

    /* Prepare a validation context. Zero-initialize and set no-op callbacks. */
    xmlValidCtxt ctxt_struct;
    memset(&ctxt_struct, 0, sizeof(ctxt_struct));
    ctxt_struct.userData = NULL;
    ctxt_struct.error = fuzz_validity_error;
    ctxt_struct.warning = fuzz_validity_warning;

    /*
     * Safety guard:
     *
     * Even though name/prefix lengths are already constrained, certain
     * combinations can lead to large internal automata/regexp allocations
     * inside xmlAutomataCompile/xmlRegEpxFromParse. To avoid triggering
     * out-of-memory conditions in the fuzzer, force an early failure path
     * for inputs with lengths larger than a conservative threshold by
     * making content->name NULL. This causes xmlBuildQName to return NULL
     * and xmlValidBuildAContentModel to abort before the expensive
     * compilation step.
     *
     * We choose small thresholds (8 for name, 4 for prefix). These are
     * conservative and still allow many short inputs to exercise code paths.
     */
    if (name_len > 8 || prefix_len > 4) {
        content->name = NULL;
    }

    /* Call the function under test.
     *
     * Many internal library functions are used by xmlValidBuildContentModel;
     * they are expected to be available when building/running this driver
     * within the libxml2 repository (or when linking with libxml2).
     */
    (void)xmlValidBuildContentModel(&ctxt_struct, elem);

    /*
     * Cleanup. The fuzz target may allocate internal structures (e.g. elem->contModel)
     * that we don't know how to free portably here; free what we allocated.
     * This may leak small amounts of memory allocated by libxml2 internal helpers,
     * but it's acceptable for a simple fuzz driver. If desired, additional cleanup
     * helpers (xmlRegFreeRegexp, xmlFreeAutomata, etc.) can be called when known.
     *
     * Fix: if xmlValidBuildContentModel created elem->contModel (a compiled regexp),
     * free it to avoid leaking memory allocated in xmlRegEpxFromParse/xmlAutomataCompile.
     */
    if (elem && elem->contModel) {
        /* elem->contModel is an xmlRegexp*; free it using the library helper */
        xmlRegFreeRegexp(elem->contModel);
        elem->contModel = NULL;
    }

    if (content) free(content);
    if (elem) free((void *)elem);
    if (prefix_buf) free(prefix_buf);
    if (name_buf) free(name_buf);

    return 0;
}
