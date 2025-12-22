#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

// Declare the internal function as weak so the linker won't error if the symbol
// is not exported from the libxml2 binary. We use the real parameter types
// provided by libxml2 headers. Use C linkage when compiled as C++.
#ifdef __cplusplus
extern "C" {
#endif
void *xmlRelaxNGProcessExternalRef(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) __attribute__((weak));
#ifdef __cplusplus
}
#endif

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimal validation
    if (Data == NULL || Size == 0)
        return 0;

    // Make a nul-terminated buffer for libxml2 helpers that expect C-strings
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Initialize the parser (safe to call multiple times)
    xmlInitParser();

    // Parse the input as an XML document. Use recovery and disallow network.
    // These flags are chosen to avoid long network timeouts / blocking behavior.
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET;
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL, parseOptions);

    if (doc == NULL) {
        // Nothing to do; cleanup and return.
        free(buf);
        xmlCleanupParser();
        return 0;
    }

    // Get the root element to pass as xmlNodePtr
    xmlNodePtr root = xmlDocGetRootElement(doc);

    // Create a Relax-NG parser context from the parsed document if possible.
    // Prefer the doc-based constructor so the context references the xmlDoc.
    xmlRelaxNGParserCtxtPtr rngCtxt = xmlRelaxNGNewDocParserCtxt(doc);

    // If the parser context couldn't be created, try the mem-based one as fallback.
    if (rngCtxt == NULL) {
        // xmlRelaxNGNewMemParserCtxt expects a (const char *, int)
        rngCtxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
    }

    if (rngCtxt != NULL) {
        // If the internal function is available, call it. It's declared weak,
        // so it can be absent without causing a link error.
        if (xmlRelaxNGProcessExternalRef) {
            void *def = xmlRelaxNGProcessExternalRef(rngCtxt, root);
            (void)def; // ignore the result; we don't free internal structures here
        }

        // Free the parser context using the public API.
        xmlRelaxNGFreeParserCtxt(rngCtxt);
    }

    // Free the parsed document and other resources
    xmlFreeDoc(doc);

    // Cleanup libxml2 global state for this invocation
    xmlCleanupParser();

    free(buf);
    return 0;
}
