#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include libxml2 headers (absolute paths from the source tree) */
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/relaxng.h"

/* Include the implementation file so the static function xmlRelaxNGCheckCombine
   is available in this translation unit. Adjust path as needed. */
#include "/src/libxml2/relaxng.c"

/* Fuzzer entry point expected by libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 (no-op in many builds, but safe to call). */
    xmlInitParser();

    /* We'll consume bytes from Data to configure the test case. */
    size_t idx = 0;

    /* Determine number of defines to create (ensure at least 2 so nextHash != NULL). */
    unsigned ndefs = 2 + (Data[idx] % 3); /* produces 2..4 */
    idx++;

    /* Guard against extremely large allocation */
    if (ndefs > 50) ndefs = 50;

    /* Allocate array of pointers for convenience */
    xmlRelaxNGDefinePtr *defs = (xmlRelaxNGDefinePtr *)calloc(ndefs, sizeof(xmlRelaxNGDefinePtr));
    if (defs == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Create xmlRelaxNGDefine structs and associated xmlNode with optional "combine" prop */
    for (unsigned i = 0; i < ndefs; i++) {
        xmlRelaxNGDefinePtr d = (xmlRelaxNGDefinePtr)calloc(1, sizeof(struct _xmlRelaxNGDefine));
        if (d == NULL) {
            /* cleanup so far */
            for (unsigned j = 0; j < i; j++) {
                if (defs[j]) {
                    if (defs[j]->node)
                        xmlFreeNode(defs[j]->node);
                    free(defs[j]);
                }
            }
            free(defs);
            xmlCleanupParser();
            return 0;
        }
        /* create a simple node to attach properties to */
        xmlNodePtr node = xmlNewNode(NULL, BAD_CAST "define");
        d->node = node;
        d->nextHash = NULL; /* will link later */

        /* Choose whether to set "combine" and what value */
        if (idx < Size) {
            uint8_t choice = Data[idx++];
            switch (choice % 4) {
                case 0:
                    xmlSetProp(node, BAD_CAST "combine", BAD_CAST "choice");
                    break;
                case 1:
                    xmlSetProp(node, BAD_CAST "combine", BAD_CAST "interleave");
                    break;
                case 2:
                    /* set an unknown value to trigger the unknown-combine path */
                    xmlSetProp(node, BAD_CAST "combine", BAD_CAST "mystery");
                    break;
                case 3:
                    /* leave missing: do not set the property */
                    break;
            }
        } else {
            /* No more input bytes: set missing to exercise missing-attribute path */
        }

        defs[i] = d;
    }

    /* Link nextHash to form a chain */
    for (unsigned i = 0; i + 1 < ndefs; i++) {
        defs[i]->nextHash = defs[i+1];
    }
    defs[ndefs-1]->nextHash = NULL;

    /* Build a name string from the remaining bytes (max 64 chars) */
    size_t remain = (idx < Size) ? (Size - idx) : 0;
    size_t namelen = remain > 64 ? 64 : remain;
    char name_buf[65];
    if (namelen == 0) {
        /* use a default name */
        strcpy(name_buf, "fuzz-name");
    } else {
        for (size_t i = 0; i < namelen; i++) {
            /* map byte to printable ASCII range 32..126 */
            name_buf[i] = (char)(32 + (Data[idx + i] % 95));
        }
        name_buf[namelen] = '\0';
    }
    const xmlChar *name = (const xmlChar *)name_buf;

    /*
     * Important fix: xmlRelaxNGCheckCombine expects a valid
     * xmlRelaxNGParserCtxtPtr (ctxt) as the 'data' parameter.
     * Passing NULL leads to dereferencing NULL inside xmlRelaxNGNewDefine.
     *
     * Create a minimal zero-initialized parser context.
     */
    xmlRelaxNGParserCtxtPtr ctxt = (xmlRelaxNGParserCtxtPtr)calloc(1, sizeof(xmlRelaxNGParserCtxt));
    if (ctxt == NULL) {
        /* cleanup and exit */
        for (unsigned i = 0; i < ndefs; i++) {
            if (defs[i]) {
                if (defs[i]->node)
                    xmlFreeNode(defs[i]->node);
                free(defs[i]);
            }
        }
        free(defs);
        xmlCleanupParser();
        return 0;
    }

    /* Ensure initial values are zero/NULL by calloc. (ctxt->defMax==0 is OK). */

    /* Call the function under test. Pass our context pointer. */
    /* Note: payload expects pointer to first define in the chain */
    xmlRelaxNGCheckCombine((void *)defs[0], (void *)ctxt, name);

    /*
     * Cleanup: free nodes and defines we allocated.
     * Note: xmlRelaxNGCheckCombine may allocate additional xmlRelaxNGDefine
     * structures and store them in ctxt->defTab. We must free those structures,
     * but we must not free the xmlNodePtr pointers again because we've freed
     * the nodes below (they are shared). So only free the xmlRelaxNGDefine
     * structs themselves (they were allocated via xmlMalloc/xmlRealloc), and
     * the defTab array.
     */

    /* Free XML nodes and the original defs array elements */
    for (unsigned i = 0; i < ndefs; i++) {
        if (defs[i]) {
            if (defs[i]->node) {
                /* xmlFreeNode will free properties attached to the node */
                xmlFreeNode(defs[i]->node);
                defs[i]->node = NULL;
            }
            free(defs[i]);
            defs[i] = NULL;
        }
    }
    free(defs);
    defs = NULL;

    /* Free any xmlRelaxNGDefine pointers allocated into ctxt->defTab by the library.
       Use xmlFree for memory allocated through xmlMalloc/xmlRealloc. */
    if (ctxt->defTab != NULL) {
        int used = ctxt->defNr;
        for (int i = 0; i < used; i++) {
            if (ctxt->defTab[i] != NULL) {
                /* The struct itself can be freed; its node pointer was pointing
                   to nodes we already freed above so we must NOT free node here. */
                xmlFree(ctxt->defTab[i]);
                ctxt->defTab[i] = NULL;
            }
        }
        xmlFree(ctxt->defTab);
        ctxt->defTab = NULL;
        ctxt->defNr = 0;
        ctxt->defMax = 0;
    }

    /* If the library created an interleaves hash table, free it.
       The code may have created ctxt->interleaves via xmlHashCreate. */
    if (ctxt->interleaves != NULL) {
        xmlHashFree(ctxt->interleaves, NULL);
        ctxt->interleaves = NULL;
    }

    /* Free the parser context structure itself. */
    free(ctxt);
    ctxt = NULL;

    /* Cleanup libxml parser global state (safe to call). */
    xmlCleanupParser();

    return 0;
}
