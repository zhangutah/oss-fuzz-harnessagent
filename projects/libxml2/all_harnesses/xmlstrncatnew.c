#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <libxml/xmlstring.h>
#include <libxml/xmlmemory.h>

/*
 Fuzz driver for:
   xmlChar * xmlStrncatNew(const xmlChar * str1, const xmlChar * str2, int len);

 Input format (interpreted from the fuzzing bytes):
   - Byte 0: control flags
       bit 0 (0x01): if set, pass NULL for str1
       bit 1 (0x02): if set, pass NULL for str2
   - Next up to 4 bytes: requested len (little-endian int32). If fewer than 4 bytes remain,
     use a single signed byte as len. If none available, len = -1.
   - Remaining bytes: split roughly in half for str1 bytes then str2 bytes. Each is
     NUL-terminated before being passed to xmlStrncatNew.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    const uint8_t *p = Data;
    size_t remaining = Size;

    /* Control byte */
    uint8_t ctrl = *p;
    p++; remaining--;

    int make_null1 = (ctrl & 0x01) != 0;
    int make_null2 = (ctrl & 0x02) != 0;

    /* If both are requested NULL, skip calling the target to avoid undefined paths */
    if (make_null1 && make_null2)
        return 0;

    /* Parse len */
    int len = -1;
    if (remaining >= 4) {
        /* little-endian 32-bit */
        len = (int)((int32_t)p[0] | ((int32_t)p[1] << 8) | ((int32_t)p[2] << 16) | ((int32_t)p[3] << 24));
        p += 4;
        remaining -= 4;
    } else if (remaining >= 1) {
        /* use one signed byte */
        len = (int)(int8_t)p[0];
        p += 1;
        remaining -= 1;
    } else {
        len = -1;
    }

    /* Split remaining bytes into two parts for str1 and str2 */
    size_t s1_size = remaining / 2;
    size_t s2_size = remaining - s1_size;

    xmlChar *tmp1 = NULL;
    xmlChar *tmp2 = NULL;
    const xmlChar *s1 = NULL;
    const xmlChar *s2 = NULL;

    if (!make_null1) {
        tmp1 = (xmlChar *)malloc(s1_size + 1);
        if (tmp1 == NULL)
            goto cleanup;
        if (s1_size > 0)
            memcpy(tmp1, p, s1_size);
        tmp1[s1_size] = 0;
        s1 = tmp1;
    }
    p += s1_size;

    if (!make_null2) {
        tmp2 = (xmlChar *)malloc(s2_size + 1);
        if (tmp2 == NULL)
            goto cleanup;
        if (s2_size > 0)
            memcpy(tmp2, p, s2_size);
        tmp2[s2_size] = 0;
        s2 = tmp2;
    }

    /* Safety: if str2 is present and len is positive but larger than provided bytes,
       clamp it to avoid reading past the supplied buffer. Negative len is handled by
       xmlStrncatNew (it will compute the length from the NUL-terminated str2). */
    if (s2 != NULL && len > (int)s2_size)
        len = (int)s2_size;

    /* Call the target function */
    xmlChar *res = xmlStrncatNew(s1, s2, len);

    /* Touch result to avoid optimizing it away, then free */
    if (res != NULL) {
        volatile unsigned char touch = res[0];
        (void)touch;
        xmlFree(res);
    }

cleanup:
    if (tmp1) free(tmp1);
    if (tmp2) free(tmp2);
    return 0;
}
