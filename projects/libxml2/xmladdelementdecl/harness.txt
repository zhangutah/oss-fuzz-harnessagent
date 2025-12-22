#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/valid.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

/*
 Fuzzer entrypoint for:
   xmlElement * xmlAddElementDecl(xmlValidCtxt * ctxt,
                                  xmlDtd * dtd,
                                  const xmlChar * name,
                                  xmlElementTypeVal type,
                                  xmlElementContent * content);
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Prepare a nul-terminated name buffer derived from the input.
       Use the whole input if small; otherwise use a prefix. */
    size_t name_len = Size;
    if (name_len > 1024)  /* keep reasonable length */
        name_len = 1024;
    xmlChar *name = (xmlChar *)malloc(name_len + 1);
    if (name == NULL)
        return 0;
    memcpy(name, Data, name_len);
    name[name_len] = '\0';

    /* Choose an element type in the valid enum range:
       XML_ELEMENT_TYPE_UNDEFINED = 0,
       XML_ELEMENT_TYPE_EMPTY = 1,
       XML_ELEMENT_TYPE_ANY = 2,
       XML_ELEMENT_TYPE_MIXED = 3,
       XML_ELEMENT_TYPE_ELEMENT = 4
       We avoid 0 (UNDEFINED) to get more code paths. */
    xmlElementTypeVal type = XML_ELEMENT_TYPE_EMPTY;
    if (Size >= 1) {
        type = (xmlElementTypeVal)((Data[0] % 4) + 1); /* 1..4 */
    }

    /* If the chosen type requires an element content, allocate one.
       According to xmlAddElementDecl, MIXED and ELEMENT require content != NULL. */
    xmlElementContent *content = NULL;
    if ((type == XML_ELEMENT_TYPE_MIXED) || (type == XML_ELEMENT_TYPE_ELEMENT)) {
        content = (xmlElementContent *)malloc(sizeof(xmlElementContent));
        if (content != NULL) {
            /* Fill fields with semi-random values derived from Data to explore parsing logic. */
            /* xmlElementContentType: XML_ELEMENT_CONTENT_PCDATA(1), ELEMENT(2), SEQ(3), OR(4) */
            content->type = (xmlElementContentType)((Size >= 2 ? (Data[1] % 4) + 1 : XML_ELEMENT_CONTENT_ELEMENT));
            /* xmlElementContentOccur: ONCE(1), OPT(2), MULT(3), PLUS(4) */
            content->ocur = (xmlElementContentOccur)((Size >= 3 ? (Data[2] % 4) + 1 : XML_ELEMENT_CONTENT_ONCE));
            /* name: point to a small, nul-terminated slice derived from input (or NULL) */
            if (Size >= 4 && Data[3] % 2 == 0) {
                /* create a small name */
                size_t nm = (Size >= 5 ? (Data[4] % 16) : 0);
                if (nm == 0) nm = 1;
                xmlChar *cname = (xmlChar *)malloc(nm + 1);
                if (cname != NULL) {
                    /* fill with repeating pattern from Data (if available) */
                    for (size_t i = 0; i < nm; ++i) {
                        cname[i] = (xmlChar)(Data[(5 + i) % Size]);
                    }
                    cname[nm] = '\0';
                    content->name = (const xmlChar *)cname;
                } else {
                    content->name = NULL;
                }
            } else {
                content->name = NULL;
            }
            /* children pointers: keep NULL to avoid complex trees (fuzzer still hits code branches) */
            content->c1 = NULL;
            content->c2 = NULL;
            content->parent = NULL;
            content->prefix = NULL;
        }
    }

    /* Allocate a minimal xmlDtd structure. xmlAddElementDecl requires dtd != NULL.
       We intentionally set doc = NULL so xmlAddElementDecl will create its own table
       with no dict (as seen in the implementation). */
    xmlDtd *dtd = (xmlDtd *)malloc(sizeof(xmlDtd));
    if (dtd != NULL) {
        /* Zero-init to reasonable defaults. Many fields are pointers; setting to 0/NULL. */
        memset(dtd, 0, sizeof(xmlDtd));
        dtd->elements = NULL;
        dtd->doc = NULL;
    }

    /* Call the target function. Pass NULL for xmlValidCtxt to exercise paths that don't need it. */
    xmlElement *elem = NULL;
    if (dtd != NULL) {
        elem = xmlAddElementDecl(NULL, dtd, (const xmlChar *)name, type, content);
        /* Free any element table allocated inside dtd by xmlAddElementDecl to avoid leaks across runs.
           xmlFreeElementTable is provided by libxml2 to free the table allocated for elements. */
        if (dtd->elements != NULL) {
            /* Cast from void* to expected type and free */
            xmlFreeElementTable((xmlElementTable *)dtd->elements);
            dtd->elements = NULL;
        }
    }

    /* Free allocated content->name if we created one */
    if (content != NULL) {
        if (content->name != NULL) {
            free((void *)content->name);
        }
        free(content);
    }

    /* Free name and dtd (note: xmlAddElementDecl may have allocated additional structures
       referenced from dtd->elements; those are freed above when present). */
    free(name);
    free(dtd);

    /* Avoid compiler warnings about elem being unused */
    (void)elem;

    return 0;
}
