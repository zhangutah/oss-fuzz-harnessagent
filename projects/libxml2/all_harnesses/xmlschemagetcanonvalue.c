/*
 Fuzz driver for:
   int xmlSchemaGetCanonValue(xmlSchemaVal * val, const xmlChar ** retValue);

 The harness creates xmlSchemaVal values only via public APIs:
  - xmlSchemaNewStringValue (for XML_SCHEMAS_STRING)
  - xmlSchemaNewQNameValue (for XML_SCHEMAS_QNAME)

 It avoids using sizeof(xmlSchemaVal) or writing into val internals (the
 struct is opaque in the headers). After use, it calls xmlSchemaFreeValue
 and frees any allocated strings as required by the library semantics.
*/

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>

/*
 * Helper: allocate an xmlChar* (using xmlMalloc) and copy up to `maxlen` bytes
 * from Data, ensuring NUL termination.
 */
static xmlChar *
make_xml_string(const uint8_t *Data, size_t Size, size_t maxlen) {
    size_t len = (Size < maxlen) ? Size : maxlen;
    if (len == 0) {
        /* allocate 1 byte for empty string */
        xmlChar *s = (xmlChar *) xmlMalloc(1);
        if (!s) return NULL;
        s[0] = '\0';
        return s;
    }
    /* allocate len+1 bytes with xmlMalloc */
    xmlChar *s = (xmlChar *) xmlMalloc(len + 1);
    if (!s)
        return NULL;
    memcpy(s, Data, len);
    s[len] = '\0';
    return s;
}

/* The fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* initialize libxml once */
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* cap working size for allocations to avoid huge memory use */
    size_t cap = (Size > 1024) ? 1024 : Size;

    /* Use first byte to choose constructor */
    const uint8_t *payload = Data + 1;
    size_t payload_size = (Size > 1) ? (Size - 1) : 0;

    xmlSchemaVal *val = NULL;

    /* choice: 0 = string, 1 = qname, fallback -> string */
    uint8_t choice = Data[0];
    if ((choice & 1) == 0) {
        /* Create a string value via public API */
        xmlChar *s = make_xml_string(payload, payload_size, cap);
        if (s == NULL) {
            return 0;
        }
        /* xmlSchemaNewStringValue expects (XML_SCHEMAS_STRING, value) */
        val = xmlSchemaNewStringValue(XML_SCHEMAS_STRING, (const xmlChar *)s);
        /* xmlSchemaNewStringValue stores the pointer as-is; xmlSchemaFreeValue()
           will free nested allocations when appropriate. If the function
           didn't accept the type it returns NULL - but its implementation
           returns NULL only if type != XML_SCHEMAS_STRING. */
        if (val == NULL) {
            /* Free our allocated string if constructor refused it */
            xmlFree(s);
            return 0;
        }
    } else {
        /* Create a QName value via public API.
           Need two parts: namespace (uri) and local name. */
        /* split payload roughly into two halves */
        size_t half = payload_size / 2;
        xmlChar *local = make_xml_string(payload, half, cap);
        xmlChar *ns = make_xml_string(payload + half, payload_size - half, cap);
        if (local == NULL) {
            if (ns) xmlFree(ns);
            return 0;
        }
        if (ns == NULL) {
            xmlFree(local);
            return 0;
        }
        /* xmlSchemaNewQNameValue(namespaceName, localName) */
        val = xmlSchemaNewQNameValue((const xmlChar *)ns, (const xmlChar *)local);
        if (val == NULL) {
            /* Constructor failed: free allocated strings */
            xmlFree(local);
            xmlFree(ns);
            return 0;
        }
        /* xmlSchemaNewQNameValue sets the pointers into the value; freeing
           will be handled by xmlSchemaFreeValue, so do not free local/ns here. */
    }

    /* Call the target function under test */
    const xmlChar *ret = NULL;
    /* Protect calls with simple checks: xmlSchemaGetCanonValue expects val and retValue not NULL */
    if (val != NULL) {
        (void)xmlSchemaGetCanonValue(val, &ret);
    }

    /* If the function returned something and ret is non-NULL, free it as documented */
    if (ret != NULL) {
        /* ret was allocated with xmlStrdup/xmlMalloc in library; release with xmlFree */
        xmlFree((void *)ret);
    }

    /* Free the constructed xmlSchemaVal and any internal allocations */
    xmlSchemaFreeValue(val);

    return 0;
}
