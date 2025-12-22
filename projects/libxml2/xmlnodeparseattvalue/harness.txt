// Fixed fuzz driver for xmlNodeParseAttValue
// Path: /src/libxml2/fuzz/regexp.c
//
// Problem: private/tree.h used types and macros (xmlChar, xmlNode, XML_HIDDEN, ...)
// that are defined in the public libxml2 headers. Including the private header
// before the public headers caused unknown-type/macro errors. Solution: include
// the public libxml2 headers first, then the private header.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Include the main public libxml header first so macros like XML_HIDDEN are defined. */
#include "/src/libxml2/libxml.h"

/* Include other public libxml2 headers so types/macros used by private headers
   are defined. */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>

/* Now include the private header that declares xmlNodeParseAttValue.
   Use the project-absolute path as in the original harness. */
#include "/src/libxml2/include/private/tree.h"

/* Fuzzer entry point (do not change signature) */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive checks */
    if (Data == NULL || Size == 0)
        return 0;

    /* Ensure libxml parser is initialized (safe to call multiple times) */
    xmlInitParser();

    /* Prepare a NUL-terminated xmlChar buffer from the fuzzer input.
       xmlNodeParseAttValue respects the provided length, but it can also
       examine the NUL, so provide one. */
    xmlChar *buf = (xmlChar *)malloc(Size + 1);
    if (buf == NULL) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = 0; /* null-terminate */

    /* Call the function under test.
       Use NULL doc and NULL parent to exercise code paths independent of
       document state. */
    xmlNode *result = NULL;
    (void)xmlNodeParseAttValue(NULL, NULL, (const xmlChar *)buf, (size_t)Size, &result);

    /* Free any nodes produced by the call */
    if (result != NULL) {
        xmlFreeNodeList(result);
    }

    free(buf);

    /* Cleanup libxml parser global state (optional for fuzzers) */
    xmlCleanupParser();

    return 0;
}