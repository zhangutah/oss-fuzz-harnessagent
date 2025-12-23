#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <libxml/xmlreader.h>
#include <libxml/parser.h>

/*
 Fuzz driver for:
   int xmlTextReaderPreservePattern(xmlTextReader * reader,
                                    const xmlChar * pattern,
                                    const xmlChar ** namespaces);

 This harness:
 - Creates a libxml2 xmlTextReader from the fuzzer input using xmlReaderForMemory.
 - Uses the input bytes (null-terminated) as the pattern (xmlChar *).
 - Sometimes supplies a small namespaces array (pair-terminated) pointing into the same buffer.
 - Calls xmlTextReaderPreservePattern and frees resources.

 Note: xmlInitParser() is called to ensure libxml is initialized.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Initialize libxml2 parser (safe to call multiple times). */
    xmlInitParser();

    /* Make a null-terminated copy of the input to use as xmlChar strings. */
    size_t bufSize = Size;
    /* clamp to INT_MAX for xmlReaderForMemory's size param if necessary */
    if (bufSize > (size_t)INT_MAX) bufSize = (size_t)INT_MAX;
    char *buf = (char *)malloc(bufSize + 1);
    if (buf == NULL) return 0;
    memcpy(buf, Data, bufSize);
    buf[bufSize] = '\0'; /* ensure C-string termination */

    /* Create a reader from the buffer. */
    /* xmlReaderForMemory(const char *buffer, int size, const char *URL,
       const char *encoding, int options); */
    int size_for_reader = (int)bufSize;
    xmlTextReaderPtr reader = xmlReaderForMemory(buf, size_for_reader, NULL, NULL, 0);
    if (reader == NULL) {
        free(buf);
        return 0;
    }

    /* Use the buffer as the pattern (xmlChar is unsigned char). */
    const xmlChar *pattern = (const xmlChar *)buf;

    /* Decide whether to supply a namespaces array or NULL.
       Simple heuristic: use Data[0] LSB to decide. */
    const xmlChar **namespaces = NULL;
    const xmlChar **ns_arr = NULL;
    if ((Data[0] & 1) != 0) {
        /*
         The namespaces array is expected to be an array of pairs:
           [URI1, prefix1, URI2, prefix2, ..., NULL, NULL]
         The pattern code checks namespaces[2*i] for NULL to detect the end.
         So allocate space for one entry + terminating NULL pair => 4 pointers.
        */
        ns_arr = (const xmlChar **)malloc(sizeof(const xmlChar *) * 4);
        if (ns_arr != NULL) {
            ns_arr[0] = pattern; /* URI */
            ns_arr[1] = pattern; /* prefix (reuse same string) */
            ns_arr[2] = NULL;    /* terminator: URI==NULL */
            ns_arr[3] = NULL;    /* terminator: prefix==NULL */
            namespaces = ns_arr;
        } else {
            namespaces = NULL;
        }
    }

    /* Call the target function under test. */
    /* xmlTextReaderPreservePattern returns an int; ignore return value. */
    (void)xmlTextReaderPreservePattern(reader, pattern, namespaces);

    /* Cleanup */
    if (ns_arr) free(ns_arr);
    xmlFreeTextReader(reader);
    free(buf);

    /* Do not call xmlCleanupParser() here; libFuzzer may call continuously.
       xmlCleanupParser() deinitializes global state and is usually called at process exit. */

    return 0;
}
