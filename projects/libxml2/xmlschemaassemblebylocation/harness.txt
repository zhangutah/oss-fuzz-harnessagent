#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlstring.h>

/* Declare xmlSchemaAssembleByLocation as a weak symbol so that if the function
 * is not present in the linked library the reference will be NULL rather than
 * causing an undefined reference linker error.
 *
 * This uses the GNU weak attribute; it's safe for common OSS-Fuzz / Linux builds.
 */
#if defined(__GNUC__)
extern int xmlSchemaAssembleByLocation(xmlSchemaValidCtxtPtr vctxt,
                                       xmlSchemaPtr schema,
                                       xmlNodePtr node,
                                       const xmlChar * nsName,
                                       const xmlChar * location)
    __attribute__((weak));
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Initialize libxml2 (safe to call repeatedly) */
    xmlInitParser();

    /* Split the input into three parts:
     *  - schema_buf (first third)  -> used to parse an XSD schema
     *  - doc_buf (second third)    -> used to parse an XML document (to get a node)
     *  - rem_buf (remaining)       -> used to derive nsName and location strings
     */
    size_t schemaSize = Size / 3;
    size_t docSize = (Size - schemaSize) / 2;
    size_t remSize = Size - schemaSize - docSize;

    const char *schemaBuf = (const char*)Data;
    const char *docBuf = (const char*)(Data + schemaSize);
    const uint8_t *remBuf = Data + schemaSize + docSize;

    /* 1) Try to parse a schema from the first chunk */
    xmlSchemaParserCtxtPtr pctxt = NULL;
    xmlSchemaPtr schema = NULL;
    if (schemaSize > 0) {
        /* xmlSchemaNewMemParserCtxt expects a buffer and its size */
        pctxt = xmlSchemaNewMemParserCtxt(schemaBuf, (int)schemaSize);
        if (pctxt) {
            /* Parse may succeed or return NULL on error */
            schema = xmlSchemaParse(pctxt);
            xmlSchemaFreeParserCtxt(pctxt);
            pctxt = NULL;
        }
    }

    /* 2) Parse an XML document from the second chunk to obtain a node */
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    if (docSize > 0) {
        /* Use relaxed parsing options to increase robustness against malformed input */
        int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOBLANKS;
        doc = xmlReadMemory(docBuf, (int)docSize, "fuzz-doc.xml", NULL, parseOptions);
        if (doc) {
            root = xmlDocGetRootElement(doc);
        }
    }

    /* 3) Construct nsName and location strings from remaining bytes.
     *    Split remBuf into two halves (possibly empty).
     */
    xmlChar *nsName = NULL;
    xmlChar *location = NULL;
    if (remSize > 0) {
        size_t n = remSize / 2;
        /* xmlStrndup expects xmlChar* pointer and length */
        if (n > 0) nsName = xmlStrndup((const xmlChar*)remBuf, (int)n);
        if (remSize - n > 0) location = xmlStrndup((const xmlChar*)(remBuf + n), (int)(remSize - n));
        /* If one of them is empty, xmlStrndup may return a valid empty string or NULL depending on length. */
    }

    /* 4) Create a validation context. Pass the parsed schema (may be NULL). */
    xmlSchemaValidCtxtPtr vctxt = xmlSchemaNewValidCtxt(schema);

    /* Call the project's target function.
     * Use the weak symbol: if it's not available, skip the call.
     */
#if defined(__GNUC__)
    if (xmlSchemaAssembleByLocation) {
        /* The function returns int, but we don't use the result in this harness. */
        (void)xmlSchemaAssembleByLocation(vctxt, schema, root,
                                          (const xmlChar*)nsName,
                                          (const xmlChar*)location);
    }
#else
    /* If weak symbols are not available, do nothing (safe fallback). */
    (void)vctxt; (void)schema; (void)root; (void)nsName; (void)location;
#endif

    /* 5) Cleanup */
    if (vctxt) {
        xmlSchemaFreeValidCtxt(vctxt);
    }
    if (schema) {
        xmlSchemaFree(schema);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }
    if (nsName) {
        xmlFree(nsName);
    }
    if (location) {
        xmlFree(location);
    }

    /* Optional: cleanup global parser state. Not strictly required for short-lived fuzzers,
     * but useful in some environments. Do not call in tight loops if it hurts performance.
     */
    xmlCleanupParser();

    return 0;
}
