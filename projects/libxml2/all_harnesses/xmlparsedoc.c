/* Fuzz driver for: xmlDoc * xmlParseDoc(const xmlChar * cur);
 * Fuzzer entry point: LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
 * Plain C.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>

/* Initialize libxml2 once in a thread-safe manner */
static pthread_once_t libxml_once = PTHREAD_ONCE_INIT;
static void libxml_initialize(void) {
    /* Initialize parser library (no-op if already initialized). */
    xmlInitParser();

    /* Historically some fuzzers disabled external entity loading by calling
       xmlDisableEntityLoader(1). That symbol may not be present in all
       libxml2 versions and can cause link errors. Do not call it here. */

    /* Suppress libxml2 error output to stderr to reduce noise during fuzzing. */
    xmlSetGenericErrorFunc(NULL, NULL);
}

/* Fuzzer entrypoint expected by libFuzzer / clusterfuzz.
   Call xmlParseDoc with the input as a NUL-terminated xmlChar string.
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Ensure library initialization runs once (thread-safe). */
    pthread_once(&libxml_once, libxml_initialize);

    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* Copy input into a NUL-terminated buffer because xmlParseDoc expects a C string. */
    unsigned char *buf = (unsigned char *)malloc(Size + 1);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0'; /* ensure termination */

    /* Call the target function. */
    xmlDocPtr doc = xmlParseDoc((const xmlChar *)buf);

    /* If parsing produced a document, free it to avoid leaks. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    free(buf);
    return 0;
}
