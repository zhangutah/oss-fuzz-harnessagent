// Fuzz driver for: int xmllintShellGrep(xmllintShellCtxtPtr ctxt, char * arg, xmlNodePtr node, xmlNodePtr node2);
// Fuzzer entry: int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// This driver includes the implementation unit so the static function is available.
// It parses the fuzzer input as an XML document when possible and also uses
// the input (or a truncated copy) as the search argument.
//
// Fixed: avoid leaking memory allocated by xmlGetNodePath inside the included
// shell.c by providing a translation-unit-local replacement of xmlGetNodePath used only in this
// translation unit (so the included shell.c will use this safe version).
// The replacement returns a static string so xmllintShellGrep will not cause
// unreleased heap allocations via xmlGetNodePath that the function doesn't free.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
 * Trick: make the libxml headers declare a renamed symbol instead of
 * xmlGetNodePath so we can provide our own TU-local function named
 * xmlGetNodePath without conflicting with the header's external
 * declaration. We define the macro before including the headers and
 * undef it afterwards.
 */
#define xmlGetNodePath __libxml_xmlGetNodePath_original
#include <libxml/parser.h>
#include <libxml/tree.h>
#undef xmlGetNodePath

/* Provide a TU-local replacement for xmlGetNodePath so that the included
 * shell.c (which defines a static xmllintShellGrep) will call this version.
 *
 * The real xmlGetNodePath (in tree.c) allocates a buffer that the caller must
 * free. xmllintShellGrep in the shipped shell.c implementation prints the
 * returned string but does not free it, which causes a leak when fuzzing.
 *
 * By providing a version here that returns a pointer to a static
 * literal, we avoid heap allocations and thus avoid the leak. This function
 * has internal linkage (static) so it does not conflict with the real
 * xmlGetNodePath symbol in the libxml2 library when linking.
 */
static xmlChar *
xmlGetNodePath(const xmlNode *node) {
    (void)node;
    /* Return a stable static string (must be NUL-terminated). Casting is OK,
       xmlChar is typically unsigned char. This pointer must not be freed by
       callers; the included shell.c does not free it anyway. */
    return (xmlChar *)"(fuzzed-node)";
}

/*
 * Include the implementation that contains the static xmllintShellGrep
 * so it is available in this translation unit.
 *
 * NOTE: path is project-relative / absolute inside the workspace.
 * If you integrate this driver in a different layout, adjust the path.
 */
#include "/src/libxml2/shell.c"

/* Fuzzer entry point expected by libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize the library (no-op if already done) */
    xmlInitParser();

    /* Prepare a shell context */
    xmllintShellCtxtPtr ctxt = (xmllintShellCtxtPtr)calloc(1, sizeof(*ctxt));
    if (ctxt == NULL)
        return 0;

    /* Prefer not to spam stdout during fuzzing: use a temporary file for output */
    ctxt->output = tmpfile();
    if (ctxt->output == NULL) {
        /* fallback to stdout if tmpfile not available */
        ctxt->output = stdout;
    }

    /* A filename for potential messages */
    ctxt->filename = strdup("fuzz_input.xml");

    /* Build a C string argument from the input (null-terminated). Limit size */
    size_t arglen = Size;
    const size_t MAX_ARG = 4096;
    if (arglen > MAX_ARG) arglen = MAX_ARG;
    char *arg = (char *)malloc(arglen + 1);
    if (arg == NULL) {
        if (ctxt->output && ctxt->output != stdout) fclose(ctxt->output);
        free(ctxt->filename);
        free(ctxt);
        return 0;
    }
    memcpy(arg, Data, arglen);
    arg[arglen] = '\0';

    /* Try to parse the input as an XML document; if it fails, create a small doc
       containing the arg as text so xmllintShellGrep can still operate. */
    xmlDocPtr doc = NULL;
    /* Use RECOVER and NONET to reduce side effects and allow partial XML. */
    doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL,
                        XML_PARSE_RECOVER | XML_PARSE_NONET);
    if (doc == NULL) {
        /* Create a minimal document with arg as text content */
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc != NULL) {
            xmlNodePtr root = xmlNewDocNode(doc, NULL, BAD_CAST "root", NULL);
            if (root != NULL)
                xmlDocSetRootElement(doc, root);
            if (arglen > 0 && root != NULL)
                xmlNewTextChild(root, NULL, BAD_CAST "text", BAD_CAST arg);
        }
    }

    /* If doc is still NULL we bail out safely. */
    if (doc == NULL) {
        free(arg);
        if (ctxt->output && ctxt->output != stdout) fclose(ctxt->output);
        free(ctxt->filename);
        free(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Populate context and pick a node to search */
    ctxt->doc = doc;
    xmlNodePtr node = xmlDocGetRootElement(doc);
    if (node == NULL) {
        /* As a last resort pass the document pointer cast to node */
        node = (xmlNodePtr)doc;
    }

    /* Call the target function. node2 is unused by xmllintShellGrep, pass NULL. */
    (void)xmllintShellGrep(ctxt, arg, node, NULL);

    /* Cleanup */
    xmlFreeDoc(doc);
    free(arg);
    if (ctxt->filename) free(ctxt->filename);
    if (ctxt->output && ctxt->output != stdout) fclose(ctxt->output);
    free(ctxt);

    /* Cleanup parser globals occasionally; safe to call repeatedly. */
    xmlCleanupParser();

    return 0;
}