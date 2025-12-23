#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * Avoid including the private parser.h here because it uses
 * XML_HIDDEN and other macros that may not be defined in this
 * build context. Forward-declare the minimal pieces we need:
 *
 * - xmlChar type
 * - xmlScanName prototype (with C linkage so it links to the C implementation)
 * - XML_SCAN_* flags used by the harness
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char xmlChar;

/* Forward declaration of the function under test (defined in libxml2 source) */
const xmlChar *xmlScanName(const xmlChar *buf, size_t maxSize, int flags);

/* Define bit flags used by xmlScanName checks. Use distinct bits. */
#define XML_SCAN_NC      0x01
#define XML_SCAN_OLD10   0x02
#define XML_SCAN_NMTOKEN 0x04

#ifdef __cplusplus
}
#endif

/* Fuzzer entry point (signature must not be changed) */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Allocate a buffer with one extra byte so xmlScanName can safely read
       a terminating byte even if Size == 0. */
    uint8_t *buf = (uint8_t *)malloc(Size + 1);
    if (!buf)
        return 0;
    if (Size)
        memcpy(buf, Data, Size);
    buf[Size] = 0; /* ensure a safe terminator for reads */

    /* Try a number of flag combinations to exercise different code paths. */
    int flags_list[] = {
        0,
        XML_SCAN_NC,
        XML_SCAN_NMTOKEN,
        XML_SCAN_OLD10,
        XML_SCAN_NC | XML_SCAN_OLD10,
        XML_SCAN_NMTOKEN | XML_SCAN_OLD10,
        XML_SCAN_NC | XML_SCAN_NMTOKEN,
        XML_SCAN_NC | XML_SCAN_NMTOKEN | XML_SCAN_OLD10
    };
    const size_t nflags = sizeof(flags_list) / sizeof(flags_list[0]);

    /* Use a volatile sink to prevent compiler optimizing-out calls. */
    static volatile size_t sink = 0;

    for (size_t i = 0; i < nflags; ++i) {
        int flags = flags_list[i];
        const xmlChar *res = xmlScanName((const xmlChar *)buf, Size, flags);
        if (res) {
            /* record the offset from start to keep result used */
            sink ^= (size_t)(res - (const xmlChar *)buf);
        } else {
            sink ^= 0xDEADBEEF;
        }
    }

    free(buf);
    (void)sink; /* silence unused warnings in some builds */
    return 0;
}
