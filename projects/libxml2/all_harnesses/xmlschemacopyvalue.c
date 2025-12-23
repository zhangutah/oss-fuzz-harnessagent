#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* Include the libxml2 schema types header (use project absolute path) */
#include "/src/libxml2/include/libxml/xmlschemastypes.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/* Fuzzer entry point required by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/*
 * Simple fuzz driver for:
 *     xmlSchemaVal * xmlSchemaCopyValue(xmlSchemaVal * val);
 *
 * Strategy:
 * - Use the first byte of the fuzzer input to pick a schema value type/construction.
 * - Use the remaining bytes as string data (null-terminated) or split into two strings
 *   for QName/NOTATION construction.
 * - Construct an xmlSchemaVal using the public constructors exposed in xmlschemastypes.h:
 *     xmlSchemaNewStringValue, xmlSchemaNewQNameValue, xmlSchemaNewNOTATIONValue
 * - Call xmlSchemaCopyValue on the constructed value.
 * - Free both the original and the copied value using xmlSchemaFreeValue.
 *
 * Note: We limit ourselves to constructors available in the public header to avoid
 * relying on internal allocation helpers.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Use the first byte as selector, rest as payload */
    uint8_t selector = Data[0];
    const uint8_t *payload = Data + 1;
    size_t plen = (Size > 0) ? (Size - 1) : 0;

    /* Prepare safe null-terminated buffers from payload */
    /* If no payload, provide an empty string */
    char *buf = NULL;
    if (plen > 0) {
        buf = (char *)malloc(plen + 1);
        if (buf == NULL)
            return 0;
        memcpy(buf, payload, plen);
        buf[plen] = '\0';
    } else {
        buf = (char *)malloc(1);
        if (buf == NULL)
            return 0;
        buf[0] = '\0';
    }

    xmlSchemaVal *val = NULL;
    xmlSchemaVal *copy = NULL;

    /* Track whether ownership of buf was transferred to the constructed xmlSchemaVal */
    bool buf_consumed = false;

    /* Map selector to a small set of constructor patterns */
    switch (selector % 6) {
    case 0:
        /* Simple string type */
        val = xmlSchemaNewStringValue(XML_SCHEMAS_STRING, (const xmlChar *)buf);
        buf_consumed = true;
        break;
    case 1:
        /* AnyURI is treated as a string-like type; constructor may reject non-string types */
        val = xmlSchemaNewStringValue(XML_SCHEMAS_ANYURI, (const xmlChar *)buf);
        /* xmlSchemaNewStringValue currently only accepts XML_SCHEMAS_STRING and will return NULL,
           so buf_consumed remains false if constructor returns NULL. We mark consumed here
           only to indicate intent; the post-check will free buf if val == NULL. */
        if (val != NULL) buf_consumed = true;
        break;
    case 2:
        /* Use token / normalized string */
        val = xmlSchemaNewStringValue(XML_SCHEMAS_TOKEN, (const xmlChar *)buf);
        if (val != NULL) buf_consumed = true;
        break;
    case 3: {
        /* QName: split payload into namespace and local name */
        size_t mid = plen / 2;
        /* Create two null-terminated strings */
        char *ns = (char *)malloc(mid + 1);
        char *local = (char *)malloc((plen - mid) + 1);
        if (ns == NULL || local == NULL) {
            free(ns);
            free(local);
            break;
        }
        if (mid > 0) memcpy(ns, payload, mid);
        ns[mid] = '\0';
        if (plen > mid) memcpy(local, payload + mid, plen - mid);
        local[plen - mid] = '\0';
        val = xmlSchemaNewQNameValue((const xmlChar *)ns, (const xmlChar *)local);
        /* If construction failed, free the temporary buffers; otherwise ownership transferred */
        if (val == NULL) {
            free(ns);
            free(local);
        }
        break;
    }
    case 4: {
        /* NOTATION: similar split but use name + namespace */
        size_t mid = plen / 2;
        char *name = (char *)malloc(mid + 1);
        char *ns = (char *)malloc((plen - mid) + 1);
        if (name == NULL || ns == NULL) {
            free(name);
            free(ns);
            break;
        }
        if (mid > 0) memcpy(name, payload, mid);
        name[mid] = '\0';
        if (plen > mid) memcpy(ns, payload + mid, plen - mid);
        ns[plen - mid] = '\0';
        val = xmlSchemaNewNOTATIONValue((const xmlChar *)name, (const xmlChar *)ns);
        /* Free only on failure; on success xmlSchemaFreeValue will free them. */
        if (val == NULL) {
            free(name);
            free(ns);
        }
        break;
    }
    default:
        /* Numeric/decimal-like types: use decimal or integer constructors as strings */
        /* Choose decimal for this case */
        val = xmlSchemaNewStringValue(XML_SCHEMAS_DECIMAL, (const xmlChar *)buf);
        if (val != NULL) buf_consumed = true;
        break;
    }

    /* If construction failed, cleanup and exit.
       Important: free buf only if constructor failed, because on success ownership
       of the pointer is transferred to the created xmlSchemaVal and will be freed
       by xmlSchemaFreeValue. For constructors that did not consume buf, free it now. */
    if (val == NULL) {
        free(buf);
        return 0;
    }

    /* If the constructor didn't consume buf (e.g. QName/NOTATION branches), free it here. */
    if (!buf_consumed) {
        free(buf);
        buf = NULL;
    }

    /* Call the target function under test */
    copy = xmlSchemaCopyValue(val);

    /* Free both original and copied values (copy may be NULL).
       xmlSchemaFreeValue will free internal pointers that were passed in above. */
    xmlSchemaFreeValue(val);
    if (copy != NULL)
        xmlSchemaFreeValue(copy);

    /* If buf was consumed by val, it was freed by xmlSchemaFreeValue above.
       Otherwise we already freed it. */
    return 0;
}
