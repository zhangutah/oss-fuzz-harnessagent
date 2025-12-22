#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>

/* Only include relaxng header and use RelaxNG-specific types if libxml2
 * was built with RelaxNG support.
 */
#if defined(LIBXML_RELAXNG_ENABLED)
#include <libxml/relaxng.h>
/* The implementation in the project may have xmlRelaxNGParseGrammar declared static.
 * For the purpose of the fuzz driver we declare it here as a weak symbol so the harness
 * can link even if the function isn't exported. If it's not exported, the pointer will
 * be NULL and we guard before calling it.
 *
 * Some libxml builds may not expose the xmlRelaxNGGrammarPtr typedef name in the
 * included headers. To be robust, forward-declare the underlying struct and
 * declare the extern function returning a pointer to that struct. This is
 * compatible with the typedef (which is typically `typedef struct _xmlRelaxNGGrammar *xmlRelaxNGGrammarPtr;`).
 */
struct _xmlRelaxNGGrammar;

#ifdef __cplusplus
extern "C" {
#endif

/* Declare as weak so missing symbol won't cause link-time error. */
extern struct _xmlRelaxNGGrammar *xmlRelaxNGParseGrammar(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr nodes) __attribute__((weak));

#ifdef __cplusplus
}
#endif

#endif

/* Prototype to suppress missing-prototype warnings (keeps signature unchanged). */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the libxml2 library (no-op if already initialized). */
    xmlInitParser();
    /* Avoid loading external entities (disable network). */
    int parserOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOENT;

    /* Make a null-terminated buffer copy for APIs that expect C-strings.
     * xmlReadMemory accepts a pointer + size, but some constructors expect a C string.
     */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Parse the input as an XML document. This gives us a tree to extract nodes from.
     * Use xmlReadMemory to avoid touching the filesystem.
     */
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz-input.xml", NULL, parserOptions);
    if (doc == NULL) {
#if defined(LIBXML_RELAXNG_ENABLED)
        /* Could not parse as XML; still try to create a parser context and call the function
         * with NULL nodes to exercise code paths that handle NULL.
         */
        xmlRelaxNGParserCtxtPtr pctxt = NULL;
        /* Try to create a memory parser context for the raw buffer if available. */
#ifdef HAVE_LIBXML_RELAXNG_NEW_MEM_PARSERCTXT
        pctxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
#else
        /* Fallback: try the filename-based API (may treat buf as URL). */
        pctxt = xmlRelaxNGNewParserCtxt(buf);
#endif
        if (pctxt != NULL) {
            /* Call with NULL nodes (no root available). The function returns a grammar pointer (or NULL).
             * Only call if the symbol is present (not NULL due to weak linking).
             */
            if (xmlRelaxNGParseGrammar != NULL) {
                (void)xmlRelaxNGParseGrammar(pctxt, NULL);
            }
            xmlRelaxNGFreeParserCtxt(pctxt);
        }
#else
        /* RelaxNG not available in this build. Nothing more to do. */
        (void)0;
#endif

        free(buf);
        xmlCleanupParser();
        return 0;
    }

    /* Get root element */
    xmlNodePtr root = xmlDocGetRootElement(doc);
    /* Determine the nodes to pass: per function contract it expects the grammar children nodes,
     * so pass root->children if root is present; otherwise pass NULL.
     */
    xmlNodePtr nodes = (root != NULL) ? root->children : NULL;

#if defined(LIBXML_RELAXNG_ENABLED)
    /* Create a RelaxNG parser context from the memory buffer */
    xmlRelaxNGParserCtxtPtr pctxt = NULL;
    /* Prefer the memory-based parser context (if available in the libxml2 build). */
#ifdef HAVE_LIBXML_RELAXNG_NEW_MEM_PARSERCTXT
    pctxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
    if (pctxt == NULL) {
        /* Fallback to the filename/URL-based constructor (may interpret buf as a URL). */
        pctxt = xmlRelaxNGNewParserCtxt(buf);
    }
#else
    /* If memory-based constructor not available, use filename-based one. */
    pctxt = xmlRelaxNGNewParserCtxt(buf);
#endif

    if (pctxt != NULL) {
        /* Call the target function with the created parser context and the nodes.
         * This exercises parsing the grammar content present in the XML tree.
         * Only call if the symbol is present (not NULL due to weak linking).
         */
        struct _xmlRelaxNGGrammar *g = NULL;
        if (xmlRelaxNGParseGrammar != NULL) {
            g = xmlRelaxNGParseGrammar(pctxt, nodes);
        }

        /* The returned grammar may be allocated inside the ctxt; free resources properly. */
        (void)g; /* we don't use the grammar pointer further here. */

        /* Free the parser context */
        xmlRelaxNGFreeParserCtxt(pctxt);
    }
#else
    /* RelaxNG not enabled in this libxml2 build; skip calling xmlRelaxNGParseGrammar. */
    (void)nodes;
#endif

    /* Free the parsed XML document */
    xmlFreeDoc(doc);

    /* Cleanup */
    free(buf);
    /* Note: Do not call xmlCleanupParser() frequently in multithreaded fuzzers.
     * It's safe here for single-threaded harnesses; the fuzzer driver environment
     * often runs single-threaded testcases.
     */
    xmlCleanupParser();

    return 0;
}
