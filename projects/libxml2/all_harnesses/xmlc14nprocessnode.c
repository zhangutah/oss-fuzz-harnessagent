#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Ensure the c14n implementation is compiled in */
#ifndef LIBXML_C14N_ENABLED
#define LIBXML_C14N_ENABLED
#endif

/* Include the implementation (project-relative/absolute path). */
/* Adjust the path if needed by your build environment. */
#include "/src/libxml2/c14n.c"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>

/* Fuzzer entry point expected by LLVM libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser */
    xmlInitParser();

    /* Parse the input bytes as an XML document.
     * Per c14n requirements the document should be loaded with:
     *   XML_PARSE_DTDATTR | XML_PARSE_NOENT
     * But xmlReadMemory returns NULL on invalid input; handle gracefully.
     */
    int options = XML_PARSE_RECOVER | XML_PARSE_DTDATTR | XML_PARSE_NOENT;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz_input.xml", "UTF-8", options);
    if (doc == NULL) {
        /* Nothing to do for invalid/empty XML */
        xmlCleanupParser();
        return 0;
    }

    /* Get a reasonable starting node: the document element (root) */
    xmlNodePtr root = xmlDocGetRootElement(doc);

    /* Allocate and initialize a xmlC14NCtx structure.
     * The xmlC14NCtx type is defined in c14n.c (we included it above).
     */
    xmlC14NCtxPtr ctx = (xmlC14NCtxPtr)calloc(1, sizeof(xmlC14NCtx));
    if (ctx == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    /* Fill the context with safe defaults */
    ctx->doc = doc;
    ctx->is_visible_callback = NULL; /* default: all nodes visible */
    ctx->user_data = NULL;
    ctx->with_comments = 0;
    /* Create a memory output buffer to avoid NULL deref if function writes */
    ctx->buf = xmlAllocOutputBuffer(NULL);
    ctx->pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT;
    ctx->parent_is_doc = 0;
    ctx->ns_rendered = NULL;
    ctx->mode = XML_C14N_1_0;
    ctx->inclusive_ns_prefixes = NULL;
    ctx->error = 0;

    /* If root is NULL we still attempt to call the function with NULL cur */
    /* Call the target function under test */
    (void)xmlC14NProcessNode(ctx, root);

    /* Clean up */
    if (ctx->buf != NULL) {
        /* Close and free output buffer */
        xmlOutputBufferClose(ctx->buf);
    }
    free(ctx);

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return 0;
}
