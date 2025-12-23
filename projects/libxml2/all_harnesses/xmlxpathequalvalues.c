#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* libxml2 headers */
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/* Ensure xmlInitParser called once */
static int libxml_inited = 0;

/* Forward declaration to avoid "no previous prototype" warnings */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static inline unsigned char read_u8(const uint8_t **data, size_t *size) {
    if (*size == 0) return 0;
    unsigned char v = **data;
    (*data)++;
    (*size)--;
    return v;
}

static inline double read_double(const uint8_t **data, size_t *size) {
    double d = 0.0;
    if (*size >= sizeof(double)) {
        /* copy bytes into double */
        memcpy(&d, *data, sizeof(double));
        *data += sizeof(double);
        *size -= sizeof(double);
    } else if (*size > 0) {
        /* build a small double from available bytes */
        unsigned char buf[8] = {0};
        size_t i;
        for (i = 0; i < *size && i < 8; i++)
            buf[i] = (*data)[i];
        memcpy(&d, buf, sizeof(double));
        *data += *size;
        *size = 0;
    }
    return d;
}

static xmlXPathObjectPtr make_value_from_input(xmlDocPtr doc, const uint8_t **data, size_t *size) {
    /* If no input left, return a default number 0.0 object */
    if (*size == 0) {
        return xmlXPathNewFloat(0.0);
    }

    unsigned char kind = read_u8(data, size) % 5;

    switch (kind) {
    case 0: { /* string */
        size_t len = (*size > 0) ? (*size) : 0;
        if (len > 256) len = 256;
        if (len == 0) {
            return xmlXPathNewCString("");
        }
        char *buf = (char *)malloc(len + 1);
        if (!buf) return xmlXPathNewCString("");
        memcpy(buf, *data, len);
        buf[len] = '\0';
        *data += len;
        *size -= len;
        xmlXPathObjectPtr obj = xmlXPathNewCString(buf);
        free(buf);
        return obj;
    }
    case 1: { /* number */
        double d = read_double(data, size);
        return xmlXPathNewFloat(d);
    }
    case 2: { /* boolean */
        unsigned char b = read_u8(data, size) & 1;
        return xmlXPathNewBoolean((int)b);
    }
    case 3: { /* nodeset: do not allocate a node to avoid possible leaks in some libxml2 paths */
        /* returning an empty nodeset (node == NULL) */
        xmlNodePtr node = NULL;
        return xmlXPathNewNodeSet(node);
    }
    case 4: { /* value tree: avoid creating a node to prevent allocations that may not be freed */
        xmlNodePtr node = NULL;
        return xmlXPathNewValueTree(node);
    }
    default:
        return xmlXPathNewFloat(0.0);
    }
}

/* The fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!libxml_inited) {
        xmlInitParser();
        /* optionally disable entity loader for safety in fuzzing environment
           Only perform the assignment if the macro exists in this libxml2 build. */
#ifdef XML_DETECT_IDS_DEFAULT
        /* xmlLoadExtDtdDefaultValue may be present in some builds; only set if the value macro exists */
        xmlLoadExtDtdDefaultValue = XML_DETECT_IDS_DEFAULT; /* noop on many builds, safe default */
#endif
        libxml_inited = 1;
    }

    /* Create a small document to attach nodes (used by node-based values) */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        /* If doc cannot be created, still try to exercise numeric/string/boolean paths */
    }

    /* Create an XPath evaluation context (used by some release paths) */
    xmlXPathContextPtr xpc = xmlXPathNewContext(doc);
    /* xmlXPathEqualValues checks ctxt->context != NULL, so we need a parser context with context set */
    xmlXPathParserContext *pctxt = (xmlXPathParserContext *)calloc(1, sizeof(xmlXPathParserContext));
    if (pctxt == NULL) {
        if (xpc) xmlXPathFreeContext(xpc);
        if (doc) xmlFreeDoc(doc);
        return 0;
    }

    /* attach evaluation context */
    pctxt->context = xpc;

    /* allocate a small stack for values */
    int stackCap = 8;
    pctxt->valueTab = (xmlXPathObject **)calloc(stackCap, sizeof(xmlXPathObject *));
    pctxt->valueMax = stackCap;
    pctxt->valueNr = 0;
    pctxt->value = NULL;

    /* Prepare two values from the fuzzer input */
    const uint8_t *ptr = Data;
    size_t remaining = Size;

    xmlXPathObjectPtr v2 = make_value_from_input(doc, &ptr, &remaining);
    xmlXPathObjectPtr v1 = make_value_from_input(doc, &ptr, &remaining);

    /* Push them onto the parser context value stack in order: valueTab[0]=v1, valueTab[1]=v2
       so xmlXPathValuePop will pop v2 then v1 (matching typical operand order). */
    if (v1 != NULL) {
        pctxt->valueTab[0] = v1;
        pctxt->valueNr++;
        pctxt->value = v1;
    }
    if (v2 != NULL) {
        pctxt->valueTab[1] = v2;
        pctxt->valueNr++;
        pctxt->value = v2;
    }

    /* Call the target function. It may free or mutate the objects in the parser context. */
    /* Guard: ensure context is non-NULL (it is xpc or NULL) */
    (void)xmlXPathEqualValues(pctxt);

    /* After the call, free any remaining values on the parser stack.
       xmlXPathEqualValues may have freed some of them already, so check for non-NULL. */
    if (pctxt->valueTab != NULL) {
        for (int i = 0; i < pctxt->valueMax; i++) {
            if (pctxt->valueTab[i] != NULL) {
                xmlXPathFreeObject(pctxt->valueTab[i]);
                pctxt->valueTab[i] = NULL;
            }
        }
        free(pctxt->valueTab);
        pctxt->valueTab = NULL;
    }

    /* Free the parser context itself */
    free(pctxt);

    /* Free XPath context and document */
    if (xpc) xmlXPathFreeContext(xpc);
    if (doc) xmlFreeDoc(doc);

    /* Note: do not call xmlCleanupParser() here; fuzzer may call this function many times. */

    return 0;
}
