#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Prefer project absolute header as returned by analysis tool */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include <libxml/parser.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Initialize the library (safe to call multiple times) */
    xmlInitParser();

    /* Split input into three parts:
       - publicId string (first third)
       - systemId string (second third)
       - document chunk to feed as the parser input (remaining bytes)
    */
    size_t pub_len = Size / 3;
    size_t sys_len = Size / 3;
    size_t doc_len = Size - pub_len - sys_len;

    char *pub_str = NULL;
    char *sys_str = NULL;
    const char *doc_ptr = NULL;
    xmlParserCtxtPtr ctxt = NULL;

    if (pub_len > 0) {
        pub_str = (char *)malloc(pub_len + 1);
        if (pub_str == NULL) goto cleanup;
        memcpy(pub_str, Data, pub_len);
        pub_str[pub_len] = '\0';
    }

    if (sys_len > 0) {
        sys_str = (char *)malloc(sys_len + 1);
        if (sys_str == NULL) goto cleanup;
        memcpy(sys_str, Data + pub_len, sys_len);
        sys_str[sys_len] = '\0';
    }

    if (doc_len > 0) {
        /* The push parser accepts a pointer and an explicit length; data need not be NUL-terminated */
        doc_ptr = (const char *)(Data + pub_len + sys_len);
    } else {
        doc_ptr = NULL;
    }

    /* Create a push parser context seeded with the document chunk (may be NULL with size 0) */
    /* xmlCreatePushParserCtxt takes a non-const char* for the chunk pointer; cast is safe here */
    int int_doc_len = (doc_len > INT_MAX) ? INT_MAX : (int)doc_len;
    ctxt = xmlCreatePushParserCtxt(NULL, NULL, doc_ptr, int_doc_len, NULL);
    if (ctxt == NULL) goto cleanup;

    /* Call the target function under test.
       publicId and systemId are xmlChar* (unsigned char*). Passing NULL is allowed, but we pass the derived strings. */
    xmlParseExternalSubset(ctxt,
                           (const xmlChar *)(pub_str ? (const unsigned char *)pub_str : NULL),
                           (const xmlChar *)(sys_str ? (const unsigned char *)sys_str : NULL));

    /* Free the document created by xmlParseExternalSubset (xmlNewDoc) --
       xmlFreeParserCtxt does NOT free ctxt->myDoc, so free it here to avoid leaks. */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    /* Clean up parser context */
    xmlFreeParserCtxt(ctxt);
    ctxt = NULL;

cleanup:
    if (pub_str) free(pub_str);
    if (sys_str) free(sys_str);

    /* Cleanup global parser state (safe to call) */
    xmlCleanupParser();

    return 0;
}
