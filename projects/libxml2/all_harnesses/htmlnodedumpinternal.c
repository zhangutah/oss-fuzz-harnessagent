#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

/* Include public libxml2 headers first so types (xmlNode, xmlOutputBuffer, xmlChar, etc.)
   are available for the private header below. Use project absolute paths as in the build.
*/
#include "/src/libxml2/include/libxml/tree.h"    /* xmlNodePtr, xmlDocPtr, xmlDocGetRootElement */
#include "/src/libxml2/include/libxml/parser.h"  /* xmlReadMemory, xmlFreeDoc, xmlDocPtr */
#include "/src/libxml2/include/libxml/xmlIO.h"   /* xmlAllocOutputBuffer, xmlOutputBufferClose */

/* private/html.h uses XML_HIDDEN macro which may not be defined in this
   compilation unit. Define it to nothing if absent to avoid preprocessor errors.
*/
#ifndef XML_HIDDEN
#define XML_HIDDEN
#endif

/* Now include the private header which declares htmlNodeDumpInternal */
#include "/src/libxml2/include/private/html.h"    /* htmlNodeDumpInternal declaration */

/* Ensure symbols have correct visibility for the fuzzer harness */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* xmlReadMemory takes an int size. Guard against overly large inputs. */
    int parseSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Parse the input bytes as an XML/HTML document in memory.
       Use NULL for URL and encoding to let the parser autodetect. */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, parseSize, NULL, NULL, 0);
    if (doc == NULL) {
        /* Parsing failed; nothing to dump. */
        return 0;
    }

    /* Allocate an output buffer with no encoder (NULL). */
    xmlOutputBuffer *outBuf = xmlAllocOutputBuffer(NULL);
    if (outBuf == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Call htmlNodeDumpInternal on the document node.
       htmlNodeDumpInternal expects an xmlNode*; casting xmlDocPtr is consistent
       with how libxml2 treats document as a node for dumping purposes. */
    htmlNodeDumpInternal(outBuf, (xmlNode *)doc, NULL, 0);

    /* Clean up: close the output buffer and free the parsed document.
       xmlOutputBufferClose will flush and free internal buffers. */
    xmlOutputBufferClose(outBuf);
    xmlFreeDoc(doc);

    /* Note: xmlCleanupParser() is intentionally not called here because
       the fuzzer keeps the process alive across multiple inputs. */

    return 0;
}
