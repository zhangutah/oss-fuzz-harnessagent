#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>

/*
 Fuzz driver for:
   void xmlRelaxNGCleanupTree(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr root);

 Fuzzer entry point:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

/* Some libxml2 builds may not export certain internal symbols.
   Declare them weak and check for existence at runtime before calling. */
#ifdef __cplusplus
extern "C" {
#endif

/* xmlRelaxNGCleanupTree may be internal in some libxml2 builds */
extern void xmlRelaxNGCleanupTree(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr root) __attribute__((weak));

/* xmlRelaxNGInitTypes may also be absent in some builds */
extern int xmlRelaxNGInitTypes(void) __attribute__((weak));

#ifdef __cplusplus
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int lib_initialized = 0;
    if (!lib_initialized) {
        /*
         Initialize libxml2 once per process. Do not call xmlCleanupParser()
         here because fuzzers typically run many inputs in the same process.
        */
        xmlInitParser();
        /* Optionally initialize Relax-NG types if available */
        if (xmlRelaxNGInitTypes)
            (void) xmlRelaxNGInitTypes();
        lib_initialized = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Parse the input buffer as an XML document. Use conservative parser flags. */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzzed.xml", NULL, parseOptions);
    if (doc == NULL)
        return 0;

    /* Get the document root node (may be NULL for weird inputs). */
    xmlNodePtr root = xmlDocGetRootElement(doc);

    /* Create a Relax-NG parser context from the parsed document. */
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewDocParserCtxt(doc);

    /*
     Call the target function if available. Many libxml2 relaxng functions expect the
     parser context to reference the document passed here; passing the doc
     created above is appropriate for fuzzing.
    */
    if (pctxt != NULL) {
        if (xmlRelaxNGCleanupTree) {
            xmlRelaxNGCleanupTree(pctxt, root);
        }
        /* Free the parser context. */
        xmlRelaxNGFreeParserCtxt(pctxt);
    }

    /* Free the parsed document. */
    xmlFreeDoc(doc);

    /*
     Do not call xmlCleanupParser() here; it would free global state used
     across multiple fuzzer inputs. The fuzzer harness (or program exit)
     can call it if desired.
    */

    return 0;
}
