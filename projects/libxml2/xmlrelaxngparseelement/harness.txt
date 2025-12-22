#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* libxml2 public headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/* Include the implementation so static functions (xmlRelaxNGParseElement and
   related helpers) are available in this TU. Adjust the path if necessary. */
#include "/src/libxml2/relaxng.c"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser environment */
    xmlInitParser();

    /* Try to parse the input bytes as an XML document */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size,
                                  "fuzz-input.xml", NULL,
                                  XML_PARSE_NONET | XML_PARSE_RECOVER);

    xmlRelaxNGParserCtxtPtr pctxt = NULL;
    xmlRelaxNGDefinePtr def = NULL;

    if (doc != NULL) {
        /* Create a parser context from the parsed document (the function
           duplicates the document internally). */
        pctxt = xmlRelaxNGNewDocParserCtxt(doc);
        if (pctxt != NULL) {
            /* Get document root and call the target function if present */
            xmlNodePtr root = xmlDocGetRootElement(doc);
            if (root != NULL) {
                def = xmlRelaxNGParseElement(pctxt, root);
                /* Don't free 'def' here: the parser context owns the
                   definitions and xmlRelaxNGFreeParserCtxt will free them.
                   Freeing it here can lead to double-free / use-after-free. */
                def = NULL;
            }
        }
        /* Free the original document (xmlRelaxNGNewDocParserCtxt duplicates it) */
        xmlFreeDoc(doc);
        doc = NULL;
    } else {
        /* If the input couldn't be parsed as XML, try creating a mem parser
           context (the parser code may parse from the buffer directly). */
        /* xmlRelaxNGNewMemParserCtxt takes const char* and int size */
        pctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
        if (pctxt != NULL) {
            /* xmlRelaxNGParseElement dereferences node without checking for NULL.
               Don't call it with NULL. Create a minimal temporary xmlDoc and node
               and pass that node to the function to avoid SEGV. */
            xmlDocPtr tmpdoc = xmlNewDoc(BAD_CAST "1.0");
            if (tmpdoc != NULL) {
                xmlNodePtr tmpnode = xmlNewDocNode(tmpdoc, NULL, BAD_CAST "fuzz-root", NULL);
                if (tmpnode != NULL) {
                    xmlDocSetRootElement(tmpdoc, tmpnode);
                    def = xmlRelaxNGParseElement(pctxt, tmpnode);
                    /* Again, don't free 'def' here; let the parser context
                       manage it to avoid double-free issues. */
                    def = NULL;
                }
                xmlFreeDoc(tmpdoc);
                tmpdoc = NULL;
            } else {
                /* As a last resort, don't call xmlRelaxNGParseElement if we can't
                   create a temporary doc/node. */
            }
        }
    }

    /* Free the parser context and cleanup */
    if (pctxt != NULL) {
        xmlRelaxNGFreeParserCtxt(pctxt);
        pctxt = NULL;
    }

    /* Clean up libxml2 global state to reduce leaks across fuzzing iterations */
    xmlCleanupParser();

    return 0;
}
