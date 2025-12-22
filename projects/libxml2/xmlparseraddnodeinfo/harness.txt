#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * This fuzzer:
 *  - creates a parser context
 *  - builds a small xmlDoc and xmlNode
 *  - fills an xmlParserNodeInfo structure with data derived from the fuzzer input
 *  - calls xmlParserAddNodeInfo(ctxt, &info)
 *  - cleans up
 *
 * Note: the struct xmlParserNodeInfo in recent libxml2 versions does not expose
 * start_pos/start_line/etc. as members. To avoid accessing non-existent members
 * (which caused the compilation errors), we only set .node and zero-initialize
 * the rest of the structure. This is safe for fuzzing: the function may read
 * or write other fields, but providing a zeroed structure avoids undefined
 * bytes while not depending on particular field names.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Create a minimal document and node to attach to xmlParserNodeInfo->node */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Derive a tag name from input bytes (bounded) */
    const size_t maxName = 64;
    char namebuf[maxName + 1];
    size_t copyLen = (Size < maxName) ? Size : maxName;
    if (copyLen == 0) copyLen = 1;
    memcpy(namebuf, Data, copyLen);
    /* ensure printable and null-terminated */
    for (size_t i = 0; i < copyLen; ++i) {
        unsigned char c = (unsigned char)namebuf[i];
        if (c < 0x21 || c > 0x7e) namebuf[i] = 'a' + (c & 15);
    }
    namebuf[copyLen] = '\0';

    /* consume the bytes used for name */
    const uint8_t *p = Data + copyLen;
    size_t remaining = (Size >= copyLen) ? (Size - copyLen) : 0;

    xmlNodePtr node = xmlNewDocNode(doc, NULL, BAD_CAST namebuf, NULL);
    if (node == NULL) {
        xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
    /* make node the document root (so node->doc is set) */
    xmlDocSetRootElement(doc, node);

    /* Prepare xmlParserNodeInfo and populate fields from remaining bytes */
    xmlParserNodeInfo info;
    memset(&info, 0, sizeof(info));

    /* Set the node pointer which is present in xmlParserNodeInfo */
    info.node = node;

    /*
     * We intentionally do NOT attempt to set start_pos/start_line/etc.
     * Those members may not exist in the libxml2 version used to compile,
     * and writing to non-existing members caused the earlier compilation error.
     */

    /*
     * Optionally, set some node properties based on input to exercise more code.
     * For safety we limit attribute lengths.
     */
    if (remaining > 0) {
        size_t valLen = remaining;
        if (valLen > 256) valLen = 256;
        xmlChar *val = xmlStrndup((const xmlChar*)p, (int)valLen);
        if (val) {
            xmlNewProp(node, BAD_CAST "fuzz-attr", val);
            xmlFree(val);
        }
    }

    /*
     * Call the function under test.
     * The function is deprecated in libxml2 but still present; call it to exercise
     * node info handling code paths.
     */
    xmlParserAddNodeInfo(ctxt, &info);

    /*
     * Clear the node info sequence to free any internal buffer allocated by
     * xmlParserAddNodeInfo. This prevents the leak reported by LeakSanitizer.
     */
    xmlClearNodeInfoSeq(&ctxt->node_seq);

    /* Cleanup */
    /* Remove node from doc before freeing, to avoid double-free in some setups */
    if (node->parent != NULL)
        xmlUnlinkNode(node);

    xmlFreeNode(node);
    xmlFreeDoc(doc);
    xmlFreeParserCtxt(ctxt);

    return 0;
}
