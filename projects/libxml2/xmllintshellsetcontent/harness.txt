// Fix: Use the real xmllintShellSetContent implementation from the project's shell.c
// by including the source file. Do not provide a fake/stub definition here.
// The harness builds in the same compilation unit, so the static function in
// shell.c will be available to call.
//
// Note: we avoid redefining types the shell.c already defines and guard
// references to fields that are conditionally compiled.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

/* Include the real implementation so the static xmllintShellSetContent
 * function from shell.c is available in this translation unit.
 *
 * The fuzz harness lives in src/libxml2/fuzz/regexp.c, and shell.c is one
 * level up in src/libxml2/shell.c so include it relatively.
 */
#include "../shell.c"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Prepare a null-terminated copy of the input to pass as 'value' */
    char *value = (char *)malloc(Size + 1);
    if (value == NULL)
        return 0;
    memcpy(value, Data, Size);
    value[Size] = '\0';

    /* Try to parse the input as an XML document. If parsing fails,
       create a small default document so we still exercise code paths. */
    xmlDocPtr doc = NULL;
    if (Size > 0) {
        /* xmlReadMemory accepts non-null-terminated buffers */
        doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL, 0);
    }
    if (doc == NULL) {
        /* Create a minimal document with a root element */
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc != NULL) {
            xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
            if (root != NULL)
                xmlDocSetRootElement(doc, root);
        }
    }

    /* If we still don't have a document, bail out gracefully */
    if (doc == NULL) {
        free(value);
        return 0;
    }

    /* Build a shell context. The xmllintShellCtxt and xmllintShellCtxtPtr
     * types are defined in shell.c that we included above.
     */
    xmllintShellCtxtPtr ctxt = (xmllintShellCtxtPtr)malloc(sizeof(xmllintShellCtxt));
    if (ctxt == NULL) {
        xmlFreeDoc(doc);
        free(value);
        return 0;
    }
    memset(ctxt, 0, sizeof(xmllintShellCtxt));
    ctxt->filename = NULL;
    ctxt->doc = doc;
    ctxt->node = xmlDocGetRootElement(doc);
#ifdef LIBXML_XPATH_ENABLED
    ctxt->pctxt = NULL; /* not needed for this test; leave NULL */
#endif
    ctxt->loaded = 0;

    /* Open a /dev/null-like sink for output to avoid cluttering logs */
#ifdef _WIN32
    ctxt->output = fopen("NUL", "w");
#else
    ctxt->output = fopen("/dev/null", "w");
#endif
    /* If opening failed, it's not fatal; set to stdout as fallback */
    if (ctxt->output == NULL)
        ctxt->output = stdout;

    /* Call the real function under test from shell.c.
     * The function is static in shell.c, but because we included shell.c,
     * the symbol is available in this TU.
     */
    (void)xmllintShellSetContent(ctxt, value, ctxt->node, NULL);

    /* Cleanup */
    if (ctxt->output && ctxt->output != stdout)
        fclose(ctxt->output);
    if (ctxt->filename)
        xmlFree(ctxt->filename);
    free(ctxt);

    xmlFreeDoc(doc);
    /* It's safe (and often useful) to call cleanup after each run */
    xmlCleanupParser();

    free(value);
    return 0;
}
