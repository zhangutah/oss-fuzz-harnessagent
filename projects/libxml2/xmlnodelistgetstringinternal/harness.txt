#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* public libxml2 headers - include these first so types/macros (xmlChar, xmlNode, XML_HIDDEN, etc.) are defined */
#include <libxml/xmlversion.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

/* Declare the internal function we want to call.
   We avoid including the private header which uses XML_HIDDEN and other internals.
   Wrap in extern "C" for C++ builds to ensure C linkage. */
#ifdef __cplusplus
extern "C" {
#endif
xmlChar *xmlNodeListGetStringInternal(const xmlNode *node, int escape, int flags);
#ifdef __cplusplus
}
#endif

/* Fuzzer entry */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser (no-op if already initialized) */
    xmlInitParser();

    /* Derive escape and flags from the first bytes of Data */
    int escape = Data[0] & 1;
    int flags = 0;

    size_t header_consumed = 1;
    if (Size >= 1 + sizeof(int)) {
        /* copy sizeof(int) bytes into flags (may include non-printable bits) */
        memcpy(&flags, Data + 1, sizeof(int));
        header_consumed = 1 + sizeof(int);
    } else if (Size >= 2) {
        /* fallback: take next byte as small flags */
        flags = Data[1];
        header_consumed = 2;
    }

    /* Ensure we have some bytes left as XML content; if not, we'll synthesize a small doc */
    xmlDocPtr doc = NULL;
    xmlNodePtr target = NULL;

    if (Size > header_consumed) {
        const char *xml_buf = (const char *)(Data + header_consumed);
        int xml_len = (int)(Size - header_consumed);

        /* Parse the buffer as XML. Use NONET to avoid network access; suppress warnings/errors. */
        int parse_options = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
        doc = xmlReadMemory(xml_buf, xml_len, "fuzz-input.xml", NULL, parse_options);
    }

    if (doc != NULL) {
        /* Prefer to pass a node list (children of root) if present */
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL && root->children != NULL) {
            target = root->children;
        } else {
            /* Fallback: use the document's children (could be text or others) */
            target = (xmlNodePtr)doc->children;
        }

        /* Call the internal function */
        xmlChar *ret = xmlNodeListGetStringInternal(target, escape, flags);
        if (ret != NULL) {
            xmlFree(ret);
        }

        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* If parsing failed, synthesize a small document containing the remaining bytes as text
       to produce a safe xmlNode list associated with a doc. */
    {
        xmlDocPtr doc2 = xmlNewDoc(BAD_CAST "1.0");
        if (doc2 == NULL) {
            xmlCleanupParser();
            return 0;
        }

        xmlNodePtr root = xmlNewDocNode(doc2, NULL, BAD_CAST "root", NULL);
        if (root == NULL) {
            xmlFreeDoc(doc2);
            xmlCleanupParser();
            return 0;
        }
        xmlDocSetRootElement(doc2, root);

        if (Size > header_consumed) {
            /* xmlNewDocText expects a null-terminated string; ensure we provide a safe NUL-terminated buffer.
               Allocate a small buffer and copy up to a reasonable limit to avoid reading arbitrary memory. */
            size_t text_len = Size - header_consumed;
            /* Limit the text length to avoid very large allocations during fuzzing. */
            const size_t MAX_TEXT_LEN = 4096;
            if (text_len > MAX_TEXT_LEN) text_len = MAX_TEXT_LEN;

            char *temp = (char *)malloc(text_len + 1);
            if (temp != NULL) {
                memcpy(temp, Data + header_consumed, text_len);
                temp[text_len] = '\0';
                xmlNodePtr textNode = xmlNewDocText(doc2, (const xmlChar *)temp);
                if (textNode != NULL)
                    xmlAddChild(root, textNode);
                free(temp);
            } else {
                /* fallback to empty text node */
                xmlNodePtr textNode = xmlNewDocText(doc2, BAD_CAST "");
                if (textNode != NULL)
                    xmlAddChild(root, textNode);
            }
        } else {
            /* no payload bytes left: create an empty text node */
            xmlNodePtr textNode = xmlNewDocText(doc2, BAD_CAST "");
            if (textNode != NULL)
                xmlAddChild(root, textNode);
        }

        /* Pass root->children (text node) into the internal function */
        target = root->children;
        xmlChar *ret = xmlNodeListGetStringInternal(target, escape, flags);
        if (ret != NULL) {
            xmlFree(ret);
        }

        xmlFreeDoc(doc2);
        xmlCleanupParser();
    }

    return 0;
}
