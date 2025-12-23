#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * Ensure the Relax-NG implementation in relaxng.c is compiled in.
 * relaxng.c is part of the project sources; include it so that the
 * (static) xmlRelaxNGParseData symbol is available in this translation unit.
 *
 * We define LIBXML_RELAXNG_ENABLED so relaxng.c compiles its code paths.
 */
#ifndef LIBXML_RELAXNG_ENABLED
#define LIBXML_RELAXNG_ENABLED
#endif

/* Include the implementation file from the project so the static function
 * xmlRelaxNGParseData is visible to this harness.
 *
 * Adjust the path below if the project layout is different. The path used
 * here matches the repository layout inspected by the assistant.
 */
#include "/src/libxml2/relaxng.c"

#include <libxml/parser.h> /* for xmlReadMemory, xmlDocGetRootElement, etc. */
#include <libxml/tree.h>   /* for xmlNodePtr / xmlNewDocNode / xmlDocSetRootElement */

/* Recursive traversal to call xmlRelaxNGParseData on element nodes */
static void
traverse_and_call(xmlRelaxNGParserCtxtPtr pctxt, xmlNodePtr node) {
    for (xmlNodePtr cur = node; cur != NULL; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            /* Call the target function under test. */
            /* xmlRelaxNGParseData returns an xmlRelaxNGDefinePtr (may be NULL). */
            (void) xmlRelaxNGParseData(pctxt, cur);
        }
        /* Recurse into children */
        if (cur->children != NULL) {
            traverse_and_call(pctxt, cur->children);
        }
    }
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser global state */
    xmlInitParser();

    /* Create a Relax-NG parser context from the input bytes.
     * The mem-parser ctxt is convenient because it accepts arbitrary buffers.
     */
    xmlRelaxNGParserCtxtPtr pctxt =
        xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);

    /* Attempt to parse the input as XML so we can obtain xmlNodePtr nodes.
     * Use RECOVER and NONET to be robust and avoid network access.
     */
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz_input.xml",
                                  NULL, XML_PARSE_RECOVER | XML_PARSE_NONET);

    if (pctxt == NULL) {
        /* If we couldn't build a parser context, still try to cleanup parser
         * state and return.  (Nothing to exercise in this case.)
         */
        if (doc != NULL)
            xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    if (doc != NULL) {
        xmlNodePtr root = xmlDocGetRootElement(doc);
        if (root != NULL) {
            /* Directly call the target function on the root as well. This
             * ensures xmlRelaxNGParseData is invoked even if traversal logic
             * for some reason doesn't hit the root element.
             */
            (void) xmlRelaxNGParseData(pctxt, root);

            traverse_and_call(pctxt, root);
        }
        xmlFreeDoc(doc);
    } else {
        /* If the input wasn't valid XML, construct a minimal <data> node
         * that resembles a Relax-NG 'data' element, with a 'type' attribute.
         * This allows exercising xmlRelaxNGParseData for non-XML inputs too.
         */
        xmlDocPtr tmpdoc = xmlNewDoc(BAD_CAST "1.0");
        if (tmpdoc != NULL) {
            xmlNodePtr node = xmlNewDocNode(tmpdoc, NULL, BAD_CAST "data", NULL);
            if (node != NULL) {
                /* Set a simple type; derive a short string from input if possible. */
                char typebuf[64] = "string";
                if (Size > 0) {
                    /* Copy up to sizeof(typebuf)-1 bytes from input, but make
                     * sure it's a valid C-string (replace non-printables).
                     */
                    size_t copy = Size < (sizeof(typebuf) - 1) ? Size : (sizeof(typebuf) - 1);
                    for (size_t i = 0; i < copy; ++i) {
                        unsigned char c = Data[i];
                        typebuf[i] = (c >= 32 && c < 127) ? (char)c : '_';
                    }
                    typebuf[copy] = '\0';
                }
                xmlDocSetRootElement(tmpdoc, node);
                xmlSetProp(node, BAD_CAST "type", BAD_CAST typebuf);

                /* Call the function under test. */
                (void) xmlRelaxNGParseData(pctxt, node);
            }
            xmlFreeDoc(tmpdoc);
        }
    }

    /* Free the Relax-NG parser context (frees associated allocations). */
    xmlRelaxNGFreeParserCtxt(pctxt);

    /* Cleanup libxml parser globals */
    xmlCleanupParser();

    return 0;
}
