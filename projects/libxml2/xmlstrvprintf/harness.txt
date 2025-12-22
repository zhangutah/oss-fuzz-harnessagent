#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

/* Include the libxml2 header that declares xmlStrVPrintf */
#include "/src/libxml2/include/libxml/xmlstring.h"

/*
 Fuzz driver for:
   int xmlStrVPrintf(xmlChar * buf, int len, const char * msg, va_list ap);

 Strategy:
 - Build a null-terminated message string from the fuzzer input.
 - Sanitize '%' characters (replace with 'X') so vsnprintf won't consume
   nonexistent variadic arguments (prevents undefined behavior).
 - Call a small wrapper that is variadic and initializes a va_list and
   forwards it to xmlStrVPrintf.
 - Use a fixed output buffer.
*/

static int
my_xmlStrVPrintf(xmlChar *buf, int len, const char *msg, ...)
{
    int ret;
    va_list ap;
    va_start(ap, msg);
    ret = xmlStrVPrintf(buf, len, msg, ap);
    va_end(ap);
    return ret;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Output buffer for xmlStrVPrintf */
    enum { OUT_SIZE = 4096 };
    xmlChar out[OUT_SIZE];
    /* Ensure buffer is deterministically initialized to avoid uninitialized reads */
    memset(out, 0, sizeof(out));

    /* Build a safe C string from fuzzer data for the format message */
    enum { MSG_SIZE = 1024 };
    char msg[MSG_SIZE];
    size_t copy_len = Size < (MSG_SIZE - 1) ? Size : (MSG_SIZE - 1);
    memcpy(msg, Data, copy_len);
    msg[copy_len] = '\0';

    /* Sanitize '%' to avoid format specifiers consuming variadic args */
    for (size_t i = 0; i < copy_len; ++i) {
        if (msg[i] == '%') msg[i] = 'X';
    }

    /* Call the variadic wrapper which initializes an (empty) va_list */
    (void) my_xmlStrVPrintf(out, (int)sizeof(out), msg);

    /* Touch the output to prevent it being optimized away */
    if (out[0] == 1) {
        /* no-op */
        (void)putchar((int)out[0]);
    }

    return 0;
}
