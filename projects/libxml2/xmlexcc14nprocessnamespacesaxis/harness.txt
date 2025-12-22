#define LIBXML_C14N_ENABLED
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* libxml2 public headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>      /* fixed: use xmlIO.h instead of non-existent output.h */
#include <libxml/xmlmemory.h>

/*
 * Include the implementation so that static/internal functions
 * such as xmlExcC14NProcessNamespacesAxis are available to the
 * fuzzer driver. Adjust path if necessary for your build environment.
 */
#include "/src/libxml2/c14n.c"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic sanity */
    if (Data == NULL || Size == 0)
        return 0;

    /* Ensure parser is initialized (safe to call repeatedly) */
    xmlInitParser();

    /* Try to parse the fuzz input as an XML document first */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc == NULL) {
        /* Fall back to creating a minimal document with a single element */
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc == NULL)
            return 0;
        xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
        if (root == NULL) {
            xmlFreeDoc(doc);
            return 0;
        }
        xmlDocSetRootElement(doc, root);
    }

    /* Prepare a canonicalization context with minimal valid fields */
    xmlC14NCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.doc = doc;
    ctx.is_visible_callback = NULL; /* default visible behavior (macro returns 1) */
    ctx.user_data = NULL;
    ctx.with_comments = 0;
    ctx.buf = NULL;
    ctx.pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT;
    ctx.parent_is_doc = 1;
    ctx.ns_rendered = xmlC14NVisibleNsStackCreate();
    /* Use exclusive mode which xmlExcC14NProcessNamespacesAxis expects */
    ctx.mode = XML_C14N_EXCLUSIVE_1_0;
    ctx.inclusive_ns_prefixes = NULL;
    ctx.error = 0;

    /* Create an output buffer so functions printing namespaces have somewhere to write */
    xmlBufferPtr outBuf = xmlBufferCreate();
    if (outBuf != NULL) {
        xmlOutputBufferPtr out = xmlOutputBufferCreateBuffer(outBuf, NULL);
        if (out != NULL) {
            ctx.buf = out;
        } else {
            /* clean up if we couldn't create the output buffer */
            xmlBufferFree(outBuf);
            outBuf = NULL;
        }
    }

    /* Choose an element node to pass to the function.
       Prefer the document element or a child element if available. */
    xmlNodePtr node = xmlDocGetRootElement(doc);
    if (node == NULL) {
        /* Should not happen since we created a root if parse failed, but guard anyway */
        xmlFreeDoc(doc);
        if (ctx.ns_rendered)
            xmlC14NVisibleNsStackDestroy(ctx.ns_rendered);
        if (ctx.buf) {
            xmlOutputBufferClose(ctx.buf);
            /* underlying xmlBuffer freed by close */
        }
        return 0;
    }
    /* Optionally pick first child element to vary targets */
    if (node->children != NULL && node->children->type == XML_ELEMENT_NODE) {
        node = node->children;
    }

    /* Determine visibility flag from input to vary coverage */
    int visible = (Data[0] & 1) ? 1 : 0;

    /* Call the target function under test */
    /* xmlExcC14NProcessNamespacesAxis is defined static in c14n.c,
       but including the c14n.c implementation above makes it available here. */
    (void)xmlExcC14NProcessNamespacesAxis(&ctx, node, visible);

    /* Cleanup */
    if (ctx.buf) {
        /* flush and close the output buffer */
        xmlOutputBufferFlush(ctx.buf);
        xmlOutputBufferClose(ctx.buf);
        /* xmlOutputBufferClose frees associated xmlBuffer */
        ctx.buf = NULL;
    }
    if (ctx.ns_rendered)
        xmlC14NVisibleNsStackDestroy(ctx.ns_rendered);

    xmlFreeDoc(doc);

    /* We intentionally do not call xmlCleanupParser() here to avoid
       expensive global cleanup/reinit on each fuzzer input. */

    return 0;
}
