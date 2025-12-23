#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define LIBXML_RELAXNG_ENABLED 1

/* Include project relaxng implementation to access internal types */
#include "relaxng.c"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml once */
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        inited = 1;
    }

    /* Build a schema string that embeds parts of the fuzzer input so the
       relax-ng parser sees input-dependent content. This improves coverage
       compared to a fixed minimal schema. */
    const char *schemaPrefix =
        "<grammar xmlns='http://relaxng.org/ns/structure/1.0'>";
    const char *schemaSuffix = "</grammar>";

    /* Determine how many input bytes to consume for the schema \"payload\". */
    size_t schemaBytes = Size;
    /* Limit to avoid overly large allocations */
    if (schemaBytes > 512)
        schemaBytes = 512;

    /* We'll create a series of simple empty elements whose names are derived
       from the input bytes, e.g. <a3f/>, to make the grammar content vary. */
    /* Estimate needed buffer size */
    size_t estInner = schemaBytes * 8 + 1;
    size_t prefixLen = strlen(schemaPrefix);
    size_t suffixLen = strlen(schemaSuffix);
    size_t schemaBufLen = prefixLen + estInner + suffixLen + 1;
    char *schemaBuf = (char *) xmlMalloc(schemaBufLen);
    if (schemaBuf == NULL) {
        /* fallback to minimal schema below */
        schemaBuf = NULL;
    } else {
        char *p = schemaBuf;
        memcpy(p, schemaPrefix, prefixLen);
        p += prefixLen;

        /* create up to schemaBytes simple tags consuming Data[0..schemaBytes-1] */
        for (size_t i = 0; i < schemaBytes; i++) {
            /* produce tag: <nXX/> where XX is byte in hex (2 chars) */
            unsigned int b = Data[i];
            int written = snprintf(p, 8, "<n%02x/>", b & 0xff);
            if (written <= 0) break;
            p += written;
            /* keep a small cap in case snprintf wrote unexpectedly more */
            if ((size_t)(p - schemaBuf) + suffixLen + 10 > schemaBufLen)
                break;
        }
        /* append suffix */
        memcpy(p, schemaSuffix, suffixLen);
        p += suffixLen;
        *p = '\0';
    }

    /* Try to parse the generated schema. If it fails, fall back to a minimal
       well-formed schema so we always have a schema object. */
    const char *fallbackSchema =
        "<grammar xmlns='http://relaxng.org/ns/structure/1.0'>"
        "</grammar>";

    xmlRelaxNGParserCtxtPtr pctxt = NULL;
    int usedAllocSchemaBuf = 0;
    if (schemaBuf != NULL) {
        /* pass computed length */
        pctxt = xmlRelaxNGNewMemParserCtxt(schemaBuf, (int)strlen(schemaBuf));
        /* remember that pctxt references our allocated buffer so we must keep it alive
           until after xmlRelaxNGParse finishes. */
        if (pctxt != NULL)
            usedAllocSchemaBuf = 1;
    }
    if (pctxt == NULL) {
        pctxt = xmlRelaxNGNewMemParserCtxt(fallbackSchema, (int)strlen(fallbackSchema));
        usedAllocSchemaBuf = 0;
    }

    if (pctxt == NULL) {
        if (schemaBuf != NULL && usedAllocSchemaBuf == 0) {
            /* shouldn't happen, but just in case free if we had allocated */
            xmlFree(schemaBuf);
            schemaBuf = NULL;
        }
        return 0;
    }

    xmlRelaxNGPtr schema = xmlRelaxNGParse(pctxt);
    /* Now it's safe to free the parser ctxt; parser has consumed input during xmlRelaxNGParse */
    xmlRelaxNGFreeParserCtxt(pctxt);

    /* Free schemaBuf only after parsing if it was the one we allocated */
    if (schemaBuf != NULL && usedAllocSchemaBuf) {
        xmlFree(schemaBuf);
        schemaBuf = NULL;
    }

    if (schema == NULL) {
        /* If schema parsing failed, ensure we don't leak and return. */
        return 0;
    }

    xmlRelaxNGValidCtxtPtr vctxt = xmlRelaxNGNewValidCtxt(schema);
    if (vctxt == NULL) {
        xmlRelaxNGFree(schema);
        return 0;
    }

    /* Construct a fake xmlRelaxNGDefine on the heap and populate fields
       using the fuzzer input. We'll split the input to create value, name
       and ns parts so the data actually influences the validation call. */

    xmlRelaxNGDefinePtr def = (xmlRelaxNGDefinePtr) xmlMalloc(sizeof(xmlRelaxNGDefine));
    if (def == NULL) {
        xmlRelaxNGFreeValidCtxt(vctxt);
        xmlRelaxNGFree(schema);
        return 0;
    }
    memset(def, 0, sizeof(xmlRelaxNGDefine));
    def->type = XML_RELAXNG_ATTRIBUTE;

    /* Partition the input:
       - Use up to first 1024 bytes for value (or entire input if smaller)
       - Next up to 16 bytes for name
       - Next up to 16 bytes for namespace
    */
    size_t idx = 0;
    size_t remaining = Size;

    /* value */
    size_t valSize = remaining;
    if (valSize > 1024) valSize = 1024;
    xmlChar *val = (xmlChar *) xmlMalloc(valSize + 1);
    if (val == NULL) {
        xmlFree(def);
        xmlRelaxNGFreeValidCtxt(vctxt);
        xmlRelaxNGFree(schema);
        return 0;
    }
    for (size_t i = 0; i < valSize; i++) {
        /* map to printable ASCII letters to avoid embedded NULs */
        val[i] = (xmlChar) ('A' + (Data[idx + i] % 26));
    }
    val[valSize] = '\0';
    def->value = val;
    idx += valSize;
    if (remaining >= valSize)
        remaining -= valSize;
    else
        remaining = 0;

    /* name */
    size_t nameLen = remaining ? (remaining > 16 ? 16 : remaining) : 0;
    if (nameLen == 0) {
        /* default name */
        xmlChar *nm = (xmlChar *) xmlMalloc(2);
        if (nm) {
            nm[0] = 'a';
            nm[1] = '\0';
            def->name = nm;
        }
    } else {
        xmlChar *nm = (xmlChar *) xmlMalloc(nameLen + 1);
        if (nm) {
            for (size_t i = 0; i < nameLen; i++) {
                nm[i] = (xmlChar) ('a' + (Data[idx + i] % 26));
            }
            nm[nameLen] = '\0';
            def->name = nm;
        }
        idx += nameLen;
        if (remaining >= nameLen)
            remaining -= nameLen;
        else
            remaining = 0;
    }

    /* ns */
    size_t nsLen = remaining ? (remaining > 16 ? 16 : remaining) : 0;
    if (nsLen == 0) {
        /* don't set namespace (leave NULL) */
        def->ns = NULL;
    } else {
        xmlChar *ns = (xmlChar *) xmlMalloc(nsLen + 1);
        if (ns) {
            for (size_t i = 0; i < nsLen; i++) {
                /* map into lowercase letters (25 choices) */
                ns[i] = (xmlChar) ('b' + (Data[idx + i] % 25));
            }
            ns[nsLen] = '\0';
            def->ns = ns;
        }
        idx += nsLen;
        if (remaining >= nsLen)
            remaining -= nsLen;
        else
            remaining = 0;
    }

    /* To actually exercise validation code paths we need to create a node
       and an attribute that will be present in the validation state's attrs[].
       Build an element and add an attribute using def->name / def->ns / def->value. */
    xmlNodePtr elem = xmlNewNode(NULL, BAD_CAST "fuzzElem");
    if (elem != NULL) {
        xmlAttrPtr attr = NULL;
        if (def->ns != NULL && def->ns[0] != '\0') {
            /* create a namespace on the element and create a namespaced attribute */
            xmlNsPtr nsNode = xmlNewNs(elem, def->ns, NULL);
            if (nsNode != NULL) {
                attr = xmlNewNsProp(elem, nsNode, def->name ? def->name : BAD_CAST "a", def->value ? def->value : BAD_CAST "");
            } else {
                /* fallback: regular attribute */
                attr = xmlNewProp(elem, def->name ? def->name : BAD_CAST "a", def->value ? def->value : BAD_CAST "");
            }
        } else {
            /* no namespace requested: create a plain attribute */
            attr = xmlNewProp(elem, def->name ? def->name : BAD_CAST "a", def->value ? def->value : BAD_CAST "");
        }

        /* Build a validation state that references this attribute so the
           validator will attempt to validate it. */
        xmlRelaxNGValidStatePtr state = (xmlRelaxNGValidStatePtr) xmlMalloc(sizeof(xmlRelaxNGValidState));
        if (state != NULL) {
            memset(state, 0, sizeof(xmlRelaxNGValidState));

            /* Prepare attrs array (one attribute) */
            state->maxAttrs = 1;
            state->attrs = (xmlAttrPtr *) xmlMalloc(sizeof(xmlAttrPtr) * state->maxAttrs);
            if (state->attrs != NULL) {
                state->nbAttrs = 1;
                state->nbAttrLeft = 1;
                state->attrs[0] = attr;
            } else {
                state->nbAttrs = 0;
                state->nbAttrLeft = 0;
            }

            state->node = elem;
            state->seq = NULL;
            state->value = NULL;
            state->endvalue = NULL;

            /* Attach our state to the validation context */
            /* Free any existing state first (shouldn't be any in new ctxt) */
            if (vctxt->state != NULL)
                xmlRelaxNGFreeValidState(vctxt, vctxt->state);
            vctxt->state = state;
        } else {
            /* cleanup if state couldn't be allocated */
            if (elem != NULL)
                xmlFreeNode(elem); /* frees attached attributes too */
            elem = NULL;
        }
    }

    /* Call the function under test */
    (void) xmlRelaxNGValidateAttribute(vctxt, def);

    /* Cleanup:
       - free validation state's attrs and struct
       - free the element (xmlFreeNode frees attributes)
       - free def and its allocated strings
       - free validation context and schema
    */
    if (vctxt->state != NULL) {
        /* xmlRelaxNGFreeValidState handles returning states to pool or freeing */
        xmlRelaxNGFreeValidState(vctxt, vctxt->state);
        vctxt->state = NULL;
    }

    /* Free the element if it still exists */
    if (elem != NULL)
        xmlFreeNode(elem);

    if (def->name) xmlFree(def->name);
    if (def->ns) xmlFree(def->ns);
    if (def->value) xmlFree(def->value);
    xmlFree(def);

    xmlRelaxNGFreeValidCtxt(vctxt);
    xmlRelaxNGFree(schema);

    /* Do not call xmlCleanupParser() for fuzzing loop stability */

    return 0;
}
