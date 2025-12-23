/*
 * Fuzz driver for: xmlDtd * xmlCopyDtd(xmlDtd * dtd);
 *
 * Notes:
 * - The call to xmlDisableEntityLoader has been removed because some libxml2
 *   distributions do not export that symbol (it has been deprecated/removed).
 * - Keep the fuzzer entry signature exactly as required by libFuzzer.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Initialize libxml2 once to avoid repeated init/cleanup across fuzz runs.
 */
static int g_libxml_inited = 0;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    if (!g_libxml_inited) {
        /* Initialize parser (no-op in some builds) */
        xmlInitParser();
        /* xmlDisableEntityLoader was removed/deprecated in some libxml2 versions,
           so we avoid calling it to keep the harness portable. */
        g_libxml_inited = 1;
    }

    /* Make a null-terminated copy so xmlReadMemory can be called safely */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Parse the fuzzed input as XML in-memory with safe options */
    int parseOptions = XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL, parseOptions);

    free(buf);

    if (doc == NULL) {
        /* Not valid XML or parse failed — nothing to fuzz further. */
        return 0;
    }

    /* Try to obtain a DTD from the parsed document */
    xmlDtdPtr dtd = NULL;
    if (doc->intSubset != NULL) dtd = doc->intSubset;
    else if (doc->extSubset != NULL) dtd = doc->extSubset;

    if (dtd != NULL) {
        /* Call the target function under test */
        xmlDtdPtr copy = xmlCopyDtd(dtd);

        /* Release the copy if created */
        if (copy != NULL) {
            xmlFreeDtd(copy);
        }
    }

    /* Free the parsed document and associated resources */
    xmlFreeDoc(doc);

    /* Do not call xmlCleanupParser() here — tearing down global state across runs is undesirable. */

    return 0;
}
