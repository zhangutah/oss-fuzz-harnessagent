#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * Ensure the relaxng implementation is included (the function to fuzz
 * is defined inside relaxng.c and is not exported in the public headers).
 * We define LIBXML_RELAXNG_ENABLED so the code in relaxng.c is compiled.
 *
 * Use the absolute path to the file in this workspace.
 */
#ifndef LIBXML_RELAXNG_ENABLED
#define LIBXML_RELAXNG_ENABLED 1
#endif

/* Include the implementation directly so static/internal symbols are visible */
#include "/src/libxml2/relaxng.c"

/*
 * LLVMFuzzer entry point.
 *
 * Strategy:
 * - Try to interpret the input bytes as an XML document via xmlReadMemory.
 *   If parsing succeeds we create a xmlRelaxNGDocParserCtxt from the doc,
 *   call xmlRelaxNGParse (which will exercise parsing internals), and then
 *   also call xmlRelaxNGCombineStart on whatever grammar the context holds.
 * - If doc parsing fails, fall back to creating a memory parser context with
 *   an explicitly null-terminated copy of the input and create a grammar
 *   via xmlRelaxNGNewGrammar and call xmlRelaxNGCombineStart on it.
 * - Clean up all allocated objects.
 *
 * The goal is to ensure the fuzzer-controlled bytes are actually parsed and
 * influence the created parser context / grammar shape so coverage changes.
 */

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 (safe to call multiple times). */
    xmlInitParser();

    xmlDocPtr doc = NULL;
    xmlRelaxNGParserCtxtPtr pctxt = NULL;
    xmlRelaxNGPtr schema = NULL;

    /* Make a null-terminated copy of the input for xmlReadMemory to be safe. */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Try to parse the input as an XML document first. Use recover/no network. */
    doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL,
                        XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);

    if (doc != NULL) {
        /* Create a RelaxNG parser context from the parsed document. */
        pctxt = xmlRelaxNGNewDocParserCtxt(doc);
        if (pctxt != NULL) {
            /* Try to parse a schema from the document (may succeed or fail). */
            schema = xmlRelaxNGParse(pctxt);

            /*
             * If the parser context has a grammar, call the target function
             * explicitly to ensure code paths in xmlRelaxNGCombineStart are hit.
             *
             * Because we included relaxng.c, we can access internal/static
             * helpers and fields like pctxt->grammar.
             */
#ifdef LIBXML_RELAXNG_ENABLED
            if (pctxt->grammar != NULL) {
                /* Call the function under test */
                xmlRelaxNGCombineStart(pctxt, pctxt->grammar);
            } else {
                /*
                 * If no grammar was produced, create a minimal grammar and call
                 * combine-start on it to still exercise the function.
                 */
                xmlRelaxNGGrammarPtr grammar = xmlRelaxNGNewGrammar(pctxt);
                if (grammar != NULL) {
                    pctxt->grammar = grammar;
                    xmlRelaxNGCombineStart(pctxt, grammar);
                    /* free grammar using internal helper (available due to inclusion) */
                    xmlRelaxNGFreeGrammar(grammar);
                    pctxt->grammar = NULL;
                }
            }
#endif
        }
    } else {
        /*
         * Fallback: create a memory parser context. Make sure we pass a
         * null-terminated buffer so any code that expects C-strings sees one.
         */
        pctxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
        if (pctxt != NULL) {
            /* Create a new grammar and attach it to the context, then call */
            xmlRelaxNGGrammarPtr grammar = xmlRelaxNGNewGrammar(pctxt);
            if (grammar != NULL) {
                pctxt->grammar = grammar;
#ifdef LIBXML_RELAXNG_ENABLED
                xmlRelaxNGCombineStart(pctxt, grammar);
#endif
                /* Free grammar using internal helper (available due to inclusion) */
                xmlRelaxNGFreeGrammar(grammar);
                pctxt->grammar = NULL;
            }
        }
    }

    /* Clean up: free schema, parser context, document, buffer, and global state. */
    if (schema != NULL)
        xmlRelaxNGFree(schema);

    if (pctxt != NULL)
        xmlRelaxNGFreeParserCtxt(pctxt);

    if (doc != NULL)
        xmlFreeDoc(doc);

    free(buf);

    xmlCleanupParser();

    return 0;
}
