#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/SAX2.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

/* Helper to copy bytes into a NUL-terminated xmlChar* allocated with malloc */
static xmlChar* copy_part(const uint8_t *src, size_t len) {
    if (len == 0) return NULL;
    xmlChar *s = (xmlChar*)malloc(len + 1);
    if (s == NULL) return NULL;
    memcpy(s, src, len);
    s[len] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* initialize libxml only once */
        xmlInitParser();
        inited = 1;
    }

    /* Create a new parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) return 0;

    /* Ensure there is a document attached as xmlSAX2EntityDecl checks ctxt->myDoc */
    ctxt->myDoc = xmlNewDoc(BAD_CAST "1.0");
    if (ctxt->myDoc == NULL) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Ensure the document has at least an internal subset so xmlAddEntity
       doesn't return XML_DTD_NO_DTD which causes xmlSAX2EntityDecl to raise
       an internal error. Create also an external DTD to cover inSubset==2. */
    if (ctxt->myDoc->intSubset == NULL) {
        if (xmlCreateIntSubset(ctxt->myDoc, BAD_CAST "fuzz", NULL, NULL) == NULL) {
            xmlFreeDoc(ctxt->myDoc);
            xmlFreeParserCtxt(ctxt);
            return 0;
        }
    }
    /* Try to create an external subset too (optional); ignore failure. */
    if (ctxt->myDoc->extSubset == NULL) {
        (void)xmlNewDtd(ctxt->myDoc, BAD_CAST "fuzz-ext", NULL, NULL);
    }

    /* Partition the input into up to 4 parts: name, publicId, systemId, content */
    if (Size == 0) {
        /* Provide minimal defaults if no input is supplied */
        xmlChar *name = BAD_CAST "fuzz";
        /* Use a valid entity type (1..5). 6 (predefined) can trigger argument errors. */
        int type = 1;
        const xmlChar *publicId = NULL;
        const xmlChar *systemId = NULL;
        xmlChar *content = NULL;

        /* Ensure ctxt->inSubset has a defined value */
        ctxt->inSubset = 0;

        xmlSAX2EntityDecl((void *)ctxt, name, type, publicId, systemId, content);

        xmlFreeDoc(ctxt->myDoc);
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Compute lengths for each partition (try to be even) */
    size_t pos = 0;
    size_t remaining = Size;

    /* At least one byte should go to name */
    size_t n_name = remaining > 0 ? (remaining / 4) : 0;
    if (n_name == 0) n_name = 1;
    if (n_name > remaining) n_name = remaining;
    remaining -= n_name;

    size_t n_public = remaining > 0 ? (remaining / 3) : 0;
    if (n_public > remaining) n_public = remaining;
    remaining -= n_public;

    size_t n_system = remaining > 0 ? (remaining / 2) : 0;
    if (n_system > remaining) n_system = remaining;
    remaining -= n_system;

    size_t n_content = remaining;

    xmlChar *name = copy_part(Data + pos, n_name);
    pos += n_name;
    xmlChar *publicId = copy_part(Data + pos, n_public);
    pos += n_public;
    xmlChar *systemId = copy_part(Data + pos, n_system);
    pos += n_system;
    xmlChar *content = copy_part(Data + pos, n_content);
    pos += n_content;

    /* If name turned out NULL (shouldn't if Size>0), provide a default */
    if (name == NULL) {
        name = (xmlChar*)malloc(2);
        if (name) { name[0] = 'a'; name[1] = '\0'; }
    }

    /* Derive an integer 'type' from the first byte */
    int type = (int)Data[0];
    /* Keep type within the valid xmlEntityType range [1..5] to avoid xmlAddEntity returning
       XML_ERR_ARGUMENT (which leads to a fatal error path). */
    type = (type & 0xFF); /* keep within 0..255 */
    type = (type % 5) + 1; /* map to 1..5 */

    /* Set ctxt->inSubset from another input byte if available to vary behavior */
    if (Size > 1) {
        int inSubset = (int)(Data[1] & 0x3); /* 0,1,2 are meaningful values */
        if (inSubset == 3) inSubset = 0; /* clamp invalid value */
        /* If external subset requested but none was created above, avoid using 2 */
        if ((inSubset == 2) && (ctxt->myDoc->extSubset == NULL)) {
            /* fallback to internal subset to avoid xmlAddEntity returning XML_DTD_NO_DTD */
            inSubset = 0;
        }
        ctxt->inSubset = inSubset;
    } else {
        ctxt->inSubset = 0;
    }

    /* Call the target function */
    xmlSAX2EntityDecl((void *)ctxt, (const xmlChar*)name, type,
                      (const xmlChar*)publicId, (const xmlChar*)systemId,
                      content);

    /* Clean up:
       - xmlSAX2EntityDecl may attach allocated data to the document (e.g., ent->URI),
         so free the document first which should release such allocations.
       - Then free the parser context.
       - Finally, free our locally allocated strings that are not attached to libxml structures.
    */
    xmlFreeDoc(ctxt->myDoc);
    xmlFreeParserCtxt(ctxt);

    if (name) free(name);
    if (publicId) free(publicId);
    if (systemId) free(systemId);
    if (content) free(content);

    return 0;
}
