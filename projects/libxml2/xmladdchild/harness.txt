#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 Fuzz driver for:
     xmlNode * xmlAddChild(xmlNode * parent, xmlNode * cur);

 The fuzzer constructs a small xmlDoc, creates a parent node and a child node
 (either an element node or a text node) using portions of the input bytes,
 calls xmlAddChild(parent, child) and then frees the document.

 Fix summary:
 - Avoid forcing p_len/c_len to 1 when there are no bytes available.
 - If body_sz == 0, produce default names without reading any bytes.
 - Ensure no memcpy reads past the provided input buffer.
*/

static xmlChar *
mk_xml_str_from_bytes(const uint8_t *data, size_t len) {
    /* If len==0, produce a small default name and do not read 'data'. */
    if (len == 0) {
        xmlChar *buf = (xmlChar *)malloc(2);
        if (!buf) return NULL;
        buf[0] = 'n';
        buf[1] = '\0';
        return buf;
    }

    /* len > 0: allocate and copy exactly len bytes, then NUL-terminate. */
    xmlChar *buf = (xmlChar *)malloc(len + 1);
    if (!buf) return NULL;
    memcpy(buf, data, len);
    buf[len] = '\0';

    /* Avoid empty first char (some libxml APIs expect non-empty names) */
    if (buf[0] == '\0')
        buf[0] = 'n';

    return buf;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser (safe to call multiple times). */
    xmlInitParser();

    /* Create a document. */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL)
        return 0;

    /*
      Input layout:
        byte 0: flags
        remaining bytes: body (may be empty)
    */
    uint8_t flags = Data[0];
    const uint8_t *body = Data + 1;
    size_t body_sz = (Size > 1) ? (Size - 1) : 0;

    size_t p_len = 0;
    size_t c_len = 0;

    if (body_sz == 0) {
        /* No input bytes for names: use zero-length marker handled by maker. */
        p_len = 0;
        c_len = 0;
    } else if (body_sz == 1) {
        /* One byte: give it to parent, child will be default */
        p_len = 1;
        c_len = 0;
    } else {
        /* Split body into two parts safely. */
        p_len = body_sz / 2;
        c_len = body_sz - p_len;
        /* p_len and c_len are guaranteed to sum to body_sz and be <= body_sz */
    }

    /* Create strings. When len == 0, mk_xml_str_from_bytes will not dereference body. */
    xmlChar *p_name = mk_xml_str_from_bytes(body, p_len);
    xmlChar *c_name = mk_xml_str_from_bytes(body + p_len, c_len);

    if (!p_name || !c_name) {
        free(p_name);
        free(c_name);
        xmlFreeDoc(doc);
        return 0;
    }

    /* Create the parent node (element) */
    xmlNodePtr parent = xmlNewDocNode(doc, NULL, p_name, NULL);
    if (parent == NULL) {
        free(p_name);
        free(c_name);
        xmlFreeDoc(doc);
        return 0;
    }

    /* Attach parent to doc so freeing doc will clean it up. */
    xmlAddChild((xmlNodePtr)doc, parent);

    /* Create the child node: text if flags&1 set, else element */
    xmlNodePtr child = NULL;
    if (flags & 1) {
        child = xmlNewText(c_name);
    } else {
        child = xmlNewDocNode(doc, NULL, c_name, NULL);
    }

    /* Call the target function under test */
    (void)xmlAddChild(parent, child);

    /* Clean up: free the document which should free the whole tree */
    xmlFreeDoc(doc);

    /* Free temporary buffers for names */
    free(p_name);
    free(c_name);

    /* Note: avoid xmlCleanupParser() inside the per-input call for sanitizer stability */

    return 0;
}
