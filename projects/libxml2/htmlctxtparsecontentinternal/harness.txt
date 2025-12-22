#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> /* for INT_MAX */

/* libxml2 public headers */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/tree.h>
#include <libxml/xmlerror.h>
#include <libxml/HTMLparser.h>
#include <libxml/encoding.h>

#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern xmlNodePtr htmlCtxtParseContentInternal(xmlParserCtxt *ctxt, xmlParserInput *input);
#ifdef __cplusplus
}
#endif

int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, NULL);
    return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    if (Size > (size_t)INT_MAX)
        return 0;

    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr)htmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    xmlParserInputBufferPtr ibuf = xmlParserInputBufferCreateMem((const char *)Data,
                                                                 (int)Size,
                                                                 XML_CHAR_ENCODING_NONE);
    if (ibuf == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    xmlParserInputPtr input = xmlNewIOInputStream(ctxt, ibuf, XML_CHAR_ENCODING_NONE);
    if (input == NULL) {
#ifdef HAVE_XML_FREE_PARSER_INPUT_BUFFER
        xmlFreeParserInputBuffer(ibuf);
#endif
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

#ifdef xmlCtxtPushInput
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        xmlFreeInputStream(input);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }
#else
    ctxt->input = input;
#endif

    if (ctxt->myDoc == NULL) {
        ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
        if (ctxt->myDoc == NULL) {
#ifdef xmlCtxtPopInput
            xmlCtxtPopInput(ctxt);
#endif
            xmlFreeInputStream(input);
            xmlFreeParserCtxt(ctxt);
            return 0;
        }
    }

    ctxt->html = 1;

    xmlNodePtr res = NULL;
    res = htmlCtxtParseContentInternal(ctxt, input);

    if (res != NULL) {
        xmlFreeNodeList(res);
    }

    xmlFreeInputStream(input);

    /* Free the temporary document created in the parser context to avoid leaks */
    if (ctxt->myDoc != NULL) {
        xmlFreeDoc(ctxt->myDoc);
        ctxt->myDoc = NULL;
    }

    xmlFreeParserCtxt(ctxt);

    return 0;
}
