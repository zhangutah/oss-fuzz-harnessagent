#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Use the public libxml2 headers only */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

/*
 * Forward-declare the private functions we need instead of including
 * include/private/parser.h which pulls in XML_HIDDEN and other internal
 * macros that may not be defined in this build environment.
 *
 * Signatures are taken from the libxml2 private headers but declared
 * here without visibility macros.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* create a parser input from memory */
xmlParserInput *xmlCtxtNewInputFromMemory(xmlParserCtxt *ctxt,
                                          const char *url,
                                          const void *mem,
                                          size_t size,
                                          const char *encoding,
                                          xmlParserInputFlags flags);

/* parse content into a node (private API used by the fuzzer target) */
xmlNodePtr xmlCtxtParseContent(xmlParserCtxt *ctxt,
                               xmlParserInput *input,
                               xmlNodePtr node,
                               int hasTextDecl);

#ifdef __cplusplus
}
#endif

/* Fuzzer entrypoint */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic sanity checks */
    if (Data == NULL || Size == 0)
        return 0;

    /* Avoid unbounded allocations from extremely large inputs */
    const size_t MAX_INPUT_BYTES = 1 << 20; /* 1 MiB */
    if (Size > MAX_INPUT_BYTES)
        Size = MAX_INPUT_BYTES;

    /* Initialize the libxml2 parser library (safe to call repeatedly) */
    xmlInitParser();

    /* Create a parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Create a simple document and a root node to pass as the "node" argument */
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    xmlNodePtr root = NULL;
    if (doc != NULL) {
        root = xmlNewDocNode(doc, NULL, (const xmlChar *)"root", NULL);
        if (root != NULL) {
            /* Set root as the document root */
            xmlDocSetRootElement(doc, root);
        }
    }

    /* Copy input into a null-terminated buffer because libxml expects C-strings */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        if (doc) xmlFreeDoc(doc);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0'; /* ensure termination */

    /*
     * Create a parser input from the string buffer.
     * Use xmlCtxtNewInputFromMemory so the input is created correctly
     * for a parser context and node-based parsing.
     *
     * Use XML_INPUT_BUF_STATIC so the parser will treat the buffer as
     * static (it won't try to free the buf pointer); we free it ourselves.
     */
    xmlParserInputPtr input = xmlCtxtNewInputFromMemory(
        ctxt,           /* parser context */
        NULL,           /* url/base (none) */
        buf,            /* buffer */
        (size_t)Size,   /* size (size_t) */
        NULL,           /* encoding (let libxml detect) */
        XML_INPUT_BUF_STATIC /* flags */
    );

    if (input != NULL) {
        /* Call the target function under test.
           hasTextDecl set to 0; fuzzed content is in the input buffer. */
        xmlNodePtr result = xmlCtxtParseContent(ctxt, input, root, 0);

        /* If a node list is returned, free it */
        if (result != NULL) {
            xmlFreeNodeList(result);
        }

        /*
         * xmlCtxtParseContent will free the parser input (xmlFreeInputStream)
         * on exit. Do not free 'input' here to avoid double-free.
         */
    }

    /* Cleanup allocated resources */
    free(buf);
    if (doc) xmlFreeDoc(doc);
    xmlFreeParserCtxt(ctxt);

    /* Optional: cleanup global parser state */
    xmlCleanupParser();

    return 0;
}
