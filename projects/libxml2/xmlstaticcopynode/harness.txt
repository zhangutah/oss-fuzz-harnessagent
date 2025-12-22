#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

/*
 * The private header /src/libxml2/include/private/tree.h defines xmlStaticCopyNode
 * but expects XML_HIDDEN and other internal macros which may not be available
 * when building an external fuzz harness. Instead of including that private
 * header, declare the internal function prototype we need here, after including
 * the public libxml headers so xmlNode/xmlDoc types are known.
 *
 * Keep the symbol name and signature exactly as used internally:
 *     xmlNode * xmlStaticCopyNode(xmlNode * node, xmlDoc * doc, xmlNode * parent, int extended);
 *
 * Note: this relies on the symbol being available in the linked libxml2 library.
 */
extern xmlNode *xmlStaticCopyNode(xmlNode *node, xmlDoc *doc, xmlNode *parent, int extended);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* make a zero-terminated buffer for libxml2 parsing convenience */
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* initialize parser (idempotent) */
    xmlInitParser();

    /* Parse the input buffer into a document. Use recover and nonet to be robust. */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL, parseOptions);

    /* free temporary buffer ASAP */
    free(buf);

    if (doc == NULL) {
        /* nothing parsed */
        return 0;
    }

    /* Create a separate target document to copy into */
    xmlDocPtr doc2 = xmlNewDoc(BAD_CAST "1.0");
    if (doc2 == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Create a parent node inside the new document to act as a parent for copies */
    xmlNodePtr parent = xmlNewNode(NULL, BAD_CAST "fuzzParent");
    if (parent != NULL)
        xmlDocSetRootElement(doc2, parent); /* sets parent->doc = doc2 */

    /* Choose a couple of candidate source nodes:
       - the document's root element (if any)
       - the document node itself (casted to xmlNodePtr) to exercise XML_DOCUMENT_NODE branch
    */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr candidates[2];
    candidates[0] = root;
    candidates[1] = (xmlNodePtr)doc; /* may be useful to hit XML_DOCUMENT_NODE handling */

    /* Try copying with different flags and parent combinations.
       For each candidate, attempt extended=0,1,2 and parent being NULL and the created parent.
    */
    for (int ci = 0; ci < 2; ++ci) {
        xmlNodePtr src = candidates[ci];
        if (src == NULL) continue;

        for (int extended = 0; extended <= 2; ++extended) {
            /* parent = NULL case, copy into doc2 without explicit parent */
            xmlNodePtr copy1 = xmlStaticCopyNode(src, doc2, NULL, extended);
            if (copy1 != NULL) {
                /* If the returned node belongs to a different doc (e.g., xmlCopyDoc was used internally),
                   free that doc. Otherwise free just the node. */
                if (copy1->doc != doc2 && copy1->doc != NULL) {
                    xmlFreeDoc(copy1->doc);
                } else {
                    xmlFreeNode(copy1);
                }
            }

            /* parent = parent node in doc2 case */
            xmlNodePtr copy2 = xmlStaticCopyNode(src, doc2, parent, extended);
            if (copy2 != NULL) {
                if (copy2->doc != doc2 && copy2->doc != NULL) {
                    xmlFreeDoc(copy2->doc);
                } else {
                    /* xmlStaticCopyNode sets copy2->parent = parent; free it explicitly */
                    xmlFreeNode(copy2);
                }
            }
        }
    }

    /* Cleanup created docs and global state */
    xmlFreeDoc(doc2);
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here; calling it repeatedly in multi-threaded fuzzers
       can lead to issues. If desired, it can be called at process exit. */

    return 0;
}
