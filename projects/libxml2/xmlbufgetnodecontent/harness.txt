#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Ensure XML_HIDDEN is defined so private headers compile in this harness. */
#ifndef XML_HIDDEN
#define XML_HIDDEN /* nothing */
#endif

/* Use the project headers discovered for the symbol and buffer API.
   (Absolute paths returned by the repository queries.) */
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/private/buf.h"

#ifdef __cplusplus
} /* extern "C" */
#endif

/*
 * Fuzzer entry point for fuzzing:
 *     int xmlBufGetNodeContent(xmlBuf * buf, const xmlNode * cur);
 *
 * This harness builds a small xmlBuf and a single node (or namespace)
 * whose content/href is taken from the fuzzer input and then calls
 * xmlBufGetNodeContent to exercise the implementation.
 *
 * Keep the required harness signature unchanged.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Pick a node kind from the input:
       0 -> XML_CDATA_SECTION_NODE
       1 -> XML_TEXT_NODE
       2 -> XML_COMMENT_NODE
       3 -> XML_PI_NODE
       4 -> XML_NAMESPACE_DECL (uses xmlNs.href)
    */
    unsigned char sel = Data[0];
    int kind = sel % 5;

    /* Use the rest of the bytes as the content/href string.
       Ensure a non-NULL NUL-terminated xmlChar* for safety. */
    size_t payload_len = (Size > 1) ? (Size - 1) : 0;
    size_t alloc_len = (payload_len > 0) ? (payload_len + 1) : 1;
    xmlChar *payload = (xmlChar *)malloc(alloc_len);
    if (payload == NULL)
        return 0;
    if (payload_len > 0) {
        memcpy(payload, Data + 1, payload_len);
        payload[payload_len] = '\0';
    } else {
        payload[0] = '\0';
    }

    /* Create an xmlBuf to collect the result. */
    xmlBuf *buf = xmlBufCreate(0);
    if (buf == NULL) {
        free(payload);
        return 0;
    }

    if (kind == 4) {
        /* Create a namespace node (xmlNs) and set href to payload.
           xmlBufGetNodeContent casts the xmlNode* to xmlNsPtr for
           XML_NAMESPACE_DECL and accesses the href field.
           Allocate with malloc and zero-initialize to avoid uninitialized reads. */
        xmlNs *ns = (xmlNs *)malloc(sizeof(xmlNs));
        if (ns == NULL) {
            xmlBufFree(buf);
            free(payload);
            return 0;
        }
        memset(ns, 0, sizeof(*ns));
        ns->href = (const xmlChar *)payload;
        ns->prefix = NULL;
        ns->type = XML_NAMESPACE_DECL;
        /* Call the target with the ns pointer cast to xmlNode* */
        (void)xmlBufGetNodeContent(buf, (const xmlNode *)ns);

        free(ns);
    } else {
        /* Create a simple xmlNode and set its type and content. */
        xmlNode *node = (xmlNode *)malloc(sizeof(xmlNode));
        if (node == NULL) {
            xmlBufFree(buf);
            free(payload);
            return 0;
        }
        memset(node, 0, sizeof(*node));

        switch (kind) {
        case 0:
            node->type = XML_CDATA_SECTION_NODE;
            break;
        case 1:
            node->type = XML_TEXT_NODE;
            break;
        case 2:
            node->type = XML_COMMENT_NODE;
            break;
        case 3:
        default:
            node->type = XML_PI_NODE;
            break;
        }

        node->content = payload;
        /* Call the function under test */
        (void)xmlBufGetNodeContent(buf, (const xmlNode *)node);

        free(node);
    }

    /* Optionally extract the buffer content and free it properly. */
    xmlChar *out = xmlBufDetach(buf);
    if (out != NULL) {
        /* xmlBufDetach returns memory allocated using libxml2's allocator;
           free it with xmlFree. */
        xmlFree(out);
    }

    xmlBufFree(buf);

    /* free our payload buffer (the node/ns href/content was not duplicated
       by this harness and xmlBuf routines copy data when appending). */
    free(payload);

    return 0;
}
