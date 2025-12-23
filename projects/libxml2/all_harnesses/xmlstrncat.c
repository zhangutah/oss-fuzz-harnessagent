#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>

/* Include the libxml2 headers (absolute paths from the project) */
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/*
 * Fuzzer entrypoint for fuzzing:
 *     xmlChar * xmlStrncat(xmlChar * cur, const xmlChar * add, int len);
 *
 * The harness maps the input bytes into:
 *  - a 32-bit signed integer 'len' (taken from the first up-to-4 bytes)
 *  - a 'cur' buffer (first half of the remaining bytes) or NULL if empty
 *  - an 'add' buffer (second half of the remaining bytes) or NULL if empty
 *
 * We allocate buffers with xmlMalloc so that xmlRealloc/xmlFree used by
 * xmlStrncat remain compatible. Returned pointers from xmlStrncat are freed
 * with xmlFree when non-NULL.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    size_t pos = 0;
    int len = 0;

    /* Extract a 32-bit signed integer from the start of Data (if available) */
    if (Size - pos >= 4) {
        /* little-endian safe manual composition to avoid alignment issues */
        len = (int)(
            ((int)Data[pos + 0]) |
            ((int)Data[pos + 1] << 8) |
            ((int)Data[pos + 2] << 16) |
            ((int)Data[pos + 3] << 24)
        );
        pos += 4;
    } else {
        /* If not enough bytes, take whatever is available */
        int tmp = 0;
        int shift = 0;
        while (pos < Size && shift < 32) {
            tmp |= ((int)Data[pos]) << shift;
            shift += 8;
            pos++;
        }
        len = tmp;
    }

    /* Remaining bytes will be split into cur and add */
    size_t remaining = (pos < Size) ? (Size - pos) : 0;
    size_t cur_len = 0;
    size_t add_len = 0;

    if (remaining == 0) {
        cur_len = 0;
        add_len = 0;
    } else if (remaining == 1) {
        /* Only one byte -> make it the 'add' buffer */
        cur_len = 0;
        add_len = 1;
    } else {
        /* Split roughly in half */
        cur_len = remaining / 2;
        add_len = remaining - cur_len;
    }

    xmlChar *cur = NULL;
    xmlChar *add = NULL;

    /* Build cur buffer (or leave NULL if cur_len == 0) */
    if (cur_len > 0) {
        /* xmlMalloc is a function pointer provided by libxml2 (usually wraps malloc) */
        cur = (xmlChar *) xmlMalloc((size_t)cur_len + 1);
        if (cur == NULL) {
            /* Allocation failed; nothing to do */
            return 0;
        }
        /* Copy data and ensure NUL termination for safe xmlStrlen usage */
        memcpy(cur, Data + pos, cur_len);
        cur[cur_len] = 0;
    } else {
        cur = NULL;
    }

    pos += cur_len;

    /* Build add buffer (or leave NULL if add_len == 0) */
    if (add_len > 0) {
        add = (xmlChar *) xmlMalloc((size_t)add_len + 1);
        if (add == NULL) {
            if (cur != NULL) xmlFree(cur);
            return 0;
        }
        memcpy(add, Data + pos, add_len);
        add[add_len] = 0; /* not necessary for xmlStrncat which reads len bytes, but safe */
    } else {
        add = NULL;
    }

    /*
     * Safety: xmlStrncat will memcpy(len) bytes from 'add' without checking
     * that 'add' actually contains that many bytes. If 'len' > actual
     * allocated add_len we will overflow. Clamp positive 'len' to add_len
     * when add != NULL to avoid heap-buffer-overflow in the target function.
     *
     * We still allow negative len values to be passed through to exercise
     * the len < 0 branch inside xmlStrncat.
     */
    int call_len = len;
    if (call_len > 0 && add != NULL && (size_t)call_len > add_len) {
        /* safe to cast because add_len <= Size which fits in size_t; call_len is int>0 */
        call_len = (int)add_len;
    }

    /*
     * Call the target function. This may reallocate 'cur' and return a new
     * pointer (or NULL).
     */
    xmlChar *res = xmlStrncat(cur, add, call_len);

    /* Free resources:
     *  - Free the result pointer if non-NULL (it may be the same as cur).
     *  - Free 'add' if allocated.
     * Note: if res == NULL xmlStrncat may have freed cur already.
     *
     * Special case: when xmlStrncat returns NULL because len < 0 it does not
     * free the input cur pointer. In that specific case we must free cur
     * here to avoid a leak. We only free cur when res == NULL and the
     * original call_len was negative; for other res==NULL cases xmlStrncat
     * already freed cur (e.g. on realloc failure) and freeing again would
     * double-free.
     */
    if (res != NULL) {
        xmlFree(res);
    } else {
        if (call_len < 0) {
            /* xmlStrncat returned NULL due to len < 0 and did NOT free cur */
            if (cur != NULL) {
                xmlFree(cur);
            }
        }
        /* Otherwise, xmlStrncat either freed cur already or cur was NULL. */
    }

    if (add != NULL) {
        xmlFree(add);
    }

    return 0;
}
