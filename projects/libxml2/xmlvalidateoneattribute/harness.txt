#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "/src/libxml2/include/libxml/valid.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/*
 Fuzz driver for:
   int xmlValidateOneAttribute(xmlValidCtxt * ctxt,
                               xmlDoc * doc,
                               xmlNode * elem,
                               xmlAttr * attr,
                               const xmlChar * value);

 The fuzzer entry point:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/* Helper to make a nul-terminated buffer from input slice */
static char* make_str(const uint8_t *Data, size_t Size, size_t from, size_t len, size_t cap) {
    if (from >= Size || len == 0) {
        char *s = (char *)malloc(1);
        if (s) s[0] = '\0';
        return s;
    }
    if (len > cap) len = cap;
    /* clamp to available bytes */
    if (from + len > Size) len = Size - from;
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, Data + from, len);
    s[len] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    xmlInitParser();

    /*
     Strategy to ensure the fuzzer data actually influences the code paths:
     - Use the input data in multiple ways:
       1) attempt to parse the whole input as an XML document (xmlReadMemory).
       2) derive element/attribute names and attribute values from slices of the input.
       3) pass both the attribute pointer and explicit value pointer (and NULL variants)
          to xmlValidateOneAttribute depending on control flags from the input.
     - This increases the chance different branches inside xmlValidateOneAttribute are exercised.
    */

    size_t pos = 0;
    unsigned char flags = Data[pos++];
    size_t remaining = (Size > pos) ? (Size - pos) : 0;

    xmlDocPtr parsed_doc = NULL;
    if (remaining > 0) {
        /* Try to parse the entire input as XML to create richer structures */
        parsed_doc = xmlReadMemory((const char *)(Data + pos), (int)remaining,
                                   "fuzz.xml", NULL,
                                   XML_PARSE_RECOVER | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
        /* It's ok if parsing fails; parsed_doc will be NULL then. */
    }

    /* Prepare strings (element name, attribute name, attribute value) from the input bytes.
       We cap lengths to small values to avoid excessive allocations. */
    const size_t MAX_NAME = 64;
    const size_t MAX_VAL = 4096;

    /* Determine slices for names/values using remaining bytes and flags */
    size_t slice1 = 0, slice2 = 0, slice3 = 0;
    if (Size - pos >= 3) {
        slice1 = 1 + (Data[pos] % MAX_NAME); /* element name len */
        slice2 = 1 + (Data[pos + 1] % MAX_NAME); /* attr name len */
        /* attribute value length use remaining bytes but cap */
        slice3 = (size_t)(Data[pos + 2]) % (MAX_VAL > 0 ? MAX_VAL : 1);
    } else if (Size - pos >= 1) {
        slice1 = 1 + (Data[pos] % MAX_NAME);
        slice2 = 1;
        slice3 = remaining > slice1 + slice2 ? remaining - (slice1 + slice2) : 0;
    } else {
        slice1 = 1;
        slice2 = 1;
        slice3 = 0;
    }

    /* Bound slices so they fit in the remaining input */
    size_t rem_after_lenbytes = (Size > pos) ? (Size - pos) : 0;
    /* We'll carve the rest starting at pos */
    size_t avail = rem_after_lenbytes;
    if (slice1 > avail) slice1 = avail;
    avail = (avail > slice1) ? (avail - slice1) : 0;
    if (slice2 > avail) slice2 = avail;
    avail = (avail > slice2) ? (avail - slice2) : 0;
    if (slice3 > avail) slice3 = avail;

    char *elemName = make_str(Data, Size, pos, slice1, MAX_NAME);
    pos += slice1;
    char *attrName = make_str(Data, Size, pos, slice2, MAX_NAME);
    pos += slice2;
    char *valBuf = make_str(Data, Size, pos, slice3, MAX_VAL);
    pos += slice3;

    /* Fallback defaults if allocation failed or produced empty names (libxml dislikes empty names) */
    if (elemName == NULL) {
        elemName = (char *)malloc(6);
        if (elemName) strcpy(elemName, "e0");
    }
    if (attrName == NULL) {
        attrName = (char *)malloc(6);
        if (attrName) strcpy(attrName, "a0");
    }
    if (elemName[0] == '\0') {
        free(elemName);
        elemName = (char *)malloc(6);
        if (elemName) strcpy(elemName, "e0");
    }
    if (attrName[0] == '\0') {
        free(attrName);
        attrName = (char *)malloc(6);
        if (attrName) strcpy(attrName, "a0");
    }
    if (valBuf == NULL) {
        valBuf = (char *)malloc(1);
        if (valBuf) valBuf[0] = '\0';
    }

    /* Create or choose a document and element to operate on */
    xmlDocPtr doc = NULL;
    xmlNodePtr elem = NULL;

    if (parsed_doc != NULL) {
        doc = parsed_doc;
        elem = xmlDocGetRootElement(doc);
        /* If parsed doc exists but has no root, create one */
        if (elem == NULL) {
            elem = xmlNewNode(NULL, (const xmlChar *)elemName);
            xmlDocSetRootElement(doc, elem);
        }
    } else {
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc != NULL) {
            elem = xmlNewNode(NULL, (const xmlChar *)elemName);
            if (elem != NULL) {
                xmlDocSetRootElement(doc, elem);
            }
        }
    }

    /* If we still don't have an element, try to create one attached to doc */
    if (elem == NULL && doc != NULL) {
        elem = xmlNewNode(NULL, (const xmlChar *)elemName);
        if (elem != NULL) xmlDocSetRootElement(doc, elem);
    }

    /* Create an attribute attached to the element using the fuzzed name/value.
       Use xmlNewProp which creates and attaches the attribute. */
    xmlAttrPtr attr = NULL;
    if (elem != NULL) {
        attr = xmlNewProp(elem, (const xmlChar *)attrName, (const xmlChar *)valBuf);
        /* xmlNewProp can return NULL on failure; that's acceptable. */
    }

    /* Create a validation context (prefer xmlNewValidCtxt) */
    xmlValidCtxt *vctxt = xmlNewValidCtxt();
    int need_free_vctxt = 0;
    static xmlValidCtxt fallback_ctxt;
    if (vctxt == NULL) {
        /* fallback to static zeroed context */
        memset(&fallback_ctxt, 0, sizeof(fallback_ctxt));
        vctxt = &fallback_ctxt;
        need_free_vctxt = 0;
    } else {
        need_free_vctxt = 1;
    }

    /* Use flags from the input to try different call variants so the fuzzer
       can exercise different branches:
         bit 0: if set, pass value pointer as valBuf, else pass NULL
         bit 1: if set, pass attr pointer (may be NULL), else pass NULL
         bit 2: if set, pass elem pointer, else pass NULL
       Also call the function multiple times with different combinations
       to maximize coverage.
    */
    const xmlChar *valuePtr = (flags & 0x1) ? (const xmlChar *)valBuf : NULL;
    xmlAttrPtr attrPtr = (flags & 0x2) ? attr : NULL;
    xmlNodePtr elemPtr = (flags & 0x4) ? elem : NULL;

    /* Primary call */
    (void)xmlValidateOneAttribute(vctxt, doc, elemPtr, attrPtr, valuePtr);

    /* Additional calls with other combinations derived from the data to increase coverage. */
    (void)xmlValidateOneAttribute(vctxt, doc, elem, attr, (const xmlChar *)valBuf);
    (void)xmlValidateOneAttribute(vctxt, doc, elem, attr, NULL);
    (void)xmlValidateOneAttribute(vctxt, doc, elem, NULL, (const xmlChar *)valBuf);
    (void)xmlValidateOneAttribute(vctxt, doc, NULL, attr, (const xmlChar *)valBuf);

    /* Cleanup */
    if (need_free_vctxt && vctxt != NULL) {
        xmlFreeValidCtxt(vctxt);
    }

    if (doc != NULL) xmlFreeDoc(doc); /* frees parsed_doc as well if used */

    free(elemName);
    free(attrName);
    free(valBuf);

    xmlCleanupParser();

    return 0;
}
