#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 Fuzzer for:
   xmlChar * xmlNodeGetContent(const xmlNode * cur);

 Fuzzing strategy:
 - Try to parse the input as an XML document via xmlReadMemory().
 - If parsing succeeds, walk the document tree and call xmlNodeGetContent()
   on every node and on each attribute (cast to xmlNodePtr) to maximize
   code paths exercised.
 - If parsing fails, create a standalone text node from the input bytes
   (up to a reasonable cap) and call xmlNodeGetContent() on it.
 - Always include explicit, unconditional calls to xmlNodeGetContent to
   ensure the target function is definitely invoked by the harness.
 - Free all returned xmlChar* with xmlFree() and clean up libxml2 objects.
*/

static void
use_node_and_children(const xmlNodePtr node) {
    if (node == NULL) return;

    /* Call xmlNodeGetContent on the node itself */
    xmlChar *content = xmlNodeGetContent((const xmlNode *)node);
    if (content != NULL) {
        xmlFree(content);
    }

    /* Call xmlNodeGetContent on attributes (attributes are represented
       by xmlAttrPtr; many libxml2 APIs treat them compatibly when cast) */
    for (xmlAttrPtr attr = node->properties; attr; attr = attr->next) {
        xmlChar *acont = xmlNodeGetContent((const xmlNode *)attr);
        if (acont != NULL) xmlFree(acont);
    }

    /* Recurse on children */
    for (xmlNodePtr child = node->children; child; child = child->next) {
        use_node_and_children(child);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();

    /* Make an explicit, unconditional call to the target to ensure it's
       invoked by the harness even in corner cases. Passing NULL is safe:
       xmlNodeGetContent(NULL) should return NULL. */
    {
        xmlChar *c = xmlNodeGetContent(NULL);
        if (c) xmlFree(c);
    }

    /* Also create a small temporary element with a text child created from
       the input and call xmlNodeGetContent on it to guarantee a non-NULL
       invocation path. */
    {
        size_t cap_quick = 1024; /* keep this small to avoid big allocations here */
        size_t quick_len = (Size > cap_quick) ? cap_quick : Size;
        int qlen = (quick_len > (size_t)INT_MAX) ? INT_MAX : (int)quick_len;

        xmlNodePtr el = xmlNewNode(NULL, BAD_CAST "fuzzer_tmp");
        if (el != NULL) {
            xmlNodePtr txt = xmlNewTextLen((const xmlChar *)Data, qlen);
            if (txt != NULL) {
                xmlAddChild(el, txt);
            }
            xmlChar *c = xmlNodeGetContent((const xmlNode *)el);
            if (c) xmlFree(c);
            xmlFreeNode(el); /* frees children too */
        }
    }

    /* Parse the input as an XML document. Use options that are
       reasonable for fuzzing: recover and disable network. Suppress
       printing errors/warnings to keep fuzzer output clean. */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL, parseOptions);

    if (doc != NULL) {
        /* Get root element and traverse, calling xmlNodeGetContent on nodes/attrs */
        xmlNodePtr root = xmlDocGetRootElement(doc);
        use_node_and_children(root);

        /* Clean up document */
        xmlFreeDoc(doc);
    } else {
        /* If parsing failed, create a simple text node from the input bytes
           and call xmlNodeGetContent on it. Limit size to avoid huge allocations. */
        size_t cap = 1024 * 1024; /* 1MB cap */
        size_t use_len = Size;
        if (use_len > cap) use_len = cap;

        /* xmlNewTextLen takes int for length; ensure it fits */
        int len = (use_len > (size_t)INT_MAX) ? INT_MAX : (int)use_len;

        /* Create an isolated text node and use it */
        xmlNodePtr txt = xmlNewTextLen((const xmlChar *)Data, len);
        if (txt != NULL) {
            xmlChar *tcontent = xmlNodeGetContent((const xmlNode *)txt);
            if (tcontent != NULL) xmlFree(tcontent);
            xmlFreeNode(txt);
        }
    }

    /* Cleanup libxml parser globals if desired */
    /* Note: xmlCleanupParser() is safe but may interfere with other threads;
       for fuzzers that run in-process repeatedly it's generally okay to omit
       unless necessary. We'll call it to be tidy. */
    xmlCleanupParser();

    return 0;
}
