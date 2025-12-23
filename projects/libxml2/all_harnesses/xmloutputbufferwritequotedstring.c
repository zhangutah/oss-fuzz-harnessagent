#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Use public libxml2 headers only (absolute paths discovered in the codebase) */
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/* The tested function is originally declared in a private header using XML_HIDDEN.
 * To avoid pulling that private header (which references XML_HIDDEN), declare the
 * function prototype here matching the definition in xmlIO.c.
 */
#ifdef __cplusplus
extern "C" {
#endif
void xmlOutputBufferWriteQuotedString(xmlOutputBuffer *buf, const xmlChar *string);
#ifdef __cplusplus
}
#endif

/* Simple write callback used by xmlOutputBuffer.
 * It accepts the buffer and length and pretends to successfully write them
 * by returning len. The context pointer is unused here.
 */
static int fuzz_write_callback(void *context, const char *buffer, int len) {
    (void)context;
    (void)buffer;
    /* Report all bytes as written */
    return len;
}

/* Simple close callback that does nothing. */
static int fuzz_close_callback(void *context) {
    (void)context;
    return 0;
}

/* Fuzzer entrypoint */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Cap the copied size to avoid excessive allocations on pathological inputs. */
    size_t max_copy = (size_t)INT_MAX - 1;
    size_t copy_size = Size;
    if (copy_size > max_copy) copy_size = max_copy;

    /* Allocate a NUL-terminated xmlChar string (xmlChar is unsigned char) */
    xmlChar *str = (xmlChar *)malloc(copy_size + 1);
    if (str == NULL) return 0;
    if (copy_size > 0) memcpy(str, Data, copy_size);
    str[copy_size] = 0; /* NUL terminate */

    /* Initialize a minimal xmlOutputBuffer with callbacks */
    xmlOutputBuffer buf;
    memset(&buf, 0, sizeof(buf));
    buf.context = NULL;
    buf.writecallback = fuzz_write_callback;
    buf.closecallback = fuzz_close_callback;
    buf.encoder = NULL;
    buf.buffer = NULL;
    buf.conv = NULL;
    buf.written = 0;
    buf.error = 0;

    /* Call the function under test */
    xmlOutputBufferWriteQuotedString(&buf, (const xmlChar *)str);

    /* Clean up */
    free(str);
    return 0;
}
