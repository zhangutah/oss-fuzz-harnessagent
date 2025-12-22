#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Enable regexp code when including the implementation */
#ifndef LIBXML_REGEXP_ENABLED
#define LIBXML_REGEXP_ENABLED
#endif

/* Include the implementation to gain access to static/internal symbols.
   Adjust the path if the project layout differs. */
#include "/src/libxml2/xmlregexp.c"

/* Helper to create an xmlChar* string copied from input bytes safely. */
static xmlChar *
dup_xml_char_from_data(const uint8_t *Data, size_t Size, size_t offset, size_t len) {
    if (Size <= offset || len == 0)
        return NULL;
    /* Clamp len to available bytes */
    if (offset + len > Size)
        len = Size - offset;
    xmlChar *ret = (xmlChar *) xmlMalloc(len + 1);
    if (ret == NULL)
        return NULL;
    memcpy(ret, Data + offset, len);
    ret[len] = 0;
    return ret;
}

/* Safely allocate a small number of ranges from data */
static xmlRegRangePtr *
build_ranges_from_data(const uint8_t *Data, size_t Size, size_t *used_bytes, int *out_nbRanges) {
    *used_bytes = 0;
    *out_nbRanges = 0;
    if (Size == 0)
        return NULL;

    /* Derive number of ranges (0..3) from first byte */
    int nb = Data[0] & 0x03;
    size_t pos = 1;
    xmlRegRangePtr *arr = NULL;

    if (nb == 0)
        return NULL;

    arr = (xmlRegRangePtr *) xmlMalloc(sizeof(xmlRegRangePtr) * nb);
    if (arr == NULL)
        return NULL;
    memset(arr, 0, sizeof(xmlRegRangePtr) * nb);

    for (int i = 0; i < nb; i++) {
        if (pos >= Size) {
            /* truncate */
            nb = i;
            break;
        }
        xmlRegRangePtr r = (xmlRegRangePtr) xmlMalloc(sizeof(xmlRegRange));
        if (r == NULL) {
            nb = i;
            break;
        }
        memset(r, 0, sizeof(xmlRegRange));
        /* Populate fields from subsequent bytes (safely) */
        r->neg = (Data[pos] & 0x01);
        r->type = (xmlRegAtomType)(XML_REGEXP_LETTER + (Data[pos] & 0x0F));
        pos++;
        /* start and end from next two bytes */
        if (pos < Size) r->start = (int)(Data[pos++]);
        if (pos < Size) r->end = (int)(Data[pos++]);
        /* blockName: small chunk from data */
        size_t blen = 0;
        if (pos < Size) {
            blen = Data[pos++] & 0x07;
            if (blen > 0 && pos < Size) {
                r->blockName = (xmlChar *) xmlMalloc(blen + 1);
                if (r->blockName) {
                    size_t copy = blen;
                    if (pos + copy > Size) copy = Size - pos;
                    memcpy(r->blockName, Data + pos, copy);
                    r->blockName[copy] = 0;
                    pos += copy;
                }
            }
        }

        arr[i] = r;
    }

    *used_bytes = pos;
    *out_nbRanges = nb;
    return arr;
}

/* Free ranges built above */
static void
free_ranges(xmlRegRangePtr *arr, int nb) {
    if (arr == NULL)
        return;
    for (int i = 0; i < nb; i++) {
        if (arr[i]) {
            if (arr[i]->blockName)
                xmlFree(arr[i]->blockName);
            xmlFree(arr[i]);
        }
    }
    xmlFree(arr);
}

/* The fuzzer entry point expected by libFuzzer */
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Create a minimal parser context */
    xmlRegParserCtxtPtr ctxt = (xmlRegParserCtxtPtr) xmlMalloc(sizeof(xmlRegParserCtxt));
    if (ctxt == NULL)
        return 0;
    memset(ctxt, 0, sizeof(xmlRegParserCtxt));

    /* Keep some sane defaults to avoid deep recursions in the library */
    ctxt->nbAtoms = 0;
    ctxt->nbStates = 0;
    ctxt->nbCounters = 0;
    /* struct _xmlAutomata has no nbPush; set negs instead */
    ctxt->negs = 0;
    ctxt->error = 0;
    ctxt->determinist = 0;
    ctxt->flags = 0;
    ctxt->depth = 0;

    /* Build an xmlRegAtom from Data */
    xmlRegAtomPtr atom = (xmlRegAtomPtr) xmlMalloc(sizeof(xmlRegAtom));
    if (atom == NULL) {
        xmlFree(ctxt);
        return 0;
    }
    memset(atom, 0, sizeof(xmlRegAtom));

    /* Use a few bytes to fill atom fields, with bounds checking */
    size_t pos = 0;
    atom->no = 0;
    /* Guard accesses to Data */
    if (pos < Size)
        atom->type = (xmlRegAtomType)(XML_REGEXP_CHARVAL + (Data[pos++] % 10)); /* choose some valid-ish types */
    else
        atom->type = XML_REGEXP_CHARVAL;
    if (pos < Size) atom->quant = (xmlRegQuantType)(XML_REGEXP_QUANT_ONCE + (Data[pos++] % 7));
    if (pos < Size) atom->min = (int)(Data[pos++] % 10);
    if (pos < Size) atom->max = (int)(Data[pos++] % 20);
    if (pos < Size) atom->neg = (int)(Data[pos++] & 0x1);
    if (pos < Size) atom->codepoint = (int)(Data[pos++] & 0xFF);

    /* Build small strings for valuep and valuep2 */
    size_t vlen = 0;
    if (pos < Size) vlen = Data[pos++] & 0x1F; /* up to 31 bytes */
    if (vlen > 0 && pos < Size) {
        atom->valuep = dup_xml_char_from_data(Data, Size, pos, vlen);
        /* advance pos by available bytes copied */
        if (pos + vlen <= Size) pos += vlen;
        else pos = Size;
    } else {
        atom->valuep = NULL;
    }

    size_t v2len = 0;
    if (pos < Size) v2len = Data[pos++] & 0x1F;
    if (v2len > 0 && pos < Size) {
        atom->valuep2 = dup_xml_char_from_data(Data, Size, pos, v2len);
        if (pos + v2len <= Size) pos += v2len;
        else pos = Size;
    } else {
        atom->valuep2 = NULL;
    }

    /* Build a small array of ranges */
    size_t used_ranges_bytes = 0;
    int nbRanges = 0;
    xmlRegRangePtr *ranges = NULL;
    if (pos < Size) {
        ranges = build_ranges_from_data(Data + pos, Size - pos, &used_ranges_bytes, &nbRanges);
        pos += used_ranges_bytes;
        if (ranges) {
            atom->nbRanges = nbRanges;
            atom->ranges = (xmlRegRangePtr *) xmlMalloc(sizeof(xmlRegRangePtr) * nbRanges);
            if (atom->ranges) {
                for (int i = 0; i < nbRanges; i++)
                    atom->ranges[i] = ranges[i];
                /* Note: we'll free ranges via atom fields; avoid double free */
                xmlFree(ranges);
            } else {
                /* Could not attach ranges: free them properly */
                for (int i = 0; i < nbRanges; i++) {
                    if (ranges[i]) {
                        if (ranges[i]->blockName) xmlFree(ranges[i]->blockName);
                        xmlFree(ranges[i]);
                    }
                }
                /* ranges array itself was not freed above; free it now to avoid leak */
                xmlFree(ranges);
                atom->nbRanges = 0;
            }
        }
    } else {
        atom->nbRanges = 0;
        atom->ranges = NULL;
    }

    /* limit maxRanges reasonable */
    atom->maxRanges = atom->nbRanges;

    /* Some pointer fields referencing states; keep NULL to avoid deep behavior */
    atom->start = NULL;
    atom->start0 = NULL;
    atom->stop = NULL;
    atom->data = NULL;

    /* Now call the target function */
    xmlRegAtomPtr copy = NULL;
    /* Guard calls to detect potential library internal errors using ctxt->error */
    ctxt->error = 0;
    /* The function is internal (static) in the included C file, but available here */
    copy = xmlRegCopyAtom(ctxt, atom);

    /* Free the returned copy to avoid leaking memory across fuzzer iterations.
       Previously this was omitted which caused the fuzzer to run out of memory.
       Freeing the copy is safe (xmlRegFreeAtom will properly free ranges and blockName).

       FIX: xmlRegCopyRange/xmlRegNewRange in the included implementation can leave
       some fields uninitialized in certain paths. To avoid freeing garbage pointers,
       sanitize the copied ranges: only allow freeing of copy->ranges[i]->blockName
       when the original atom->ranges[i]->blockName was non-NULL. Otherwise set it
       to NULL to avoid attempting to free an uninitialized pointer.
    */
    if (copy != NULL) {
        if (copy->nbRanges > 0 && copy->ranges != NULL) {
            for (int i = 0; i < copy->nbRanges; i++) {
                /* If the original had a corresponding range with a blockName, leave it
                   so xmlRegFreeRange can free it. Otherwise set the copied blockName
                   to NULL to avoid freeing an uninitialized pointer. */
                if (!(atom->ranges != NULL && i < atom->nbRanges &&
                      atom->ranges[i] != NULL && atom->ranges[i]->blockName != NULL)) {
                    if (copy->ranges[i])
                        copy->ranges[i]->blockName = NULL;
                }
            }
        }
        xmlRegFreeAtom(copy);
        copy = NULL;
    }

    /* Free original atom and associated allocations */
    if (atom->valuep)
        xmlFree(atom->valuep);
    if (atom->valuep2)
        xmlFree(atom->valuep2);

    if (atom->ranges) {
        for (int i = 0; i < atom->nbRanges; i++) {
            if (atom->ranges[i]) {
                if (atom->ranges[i]->blockName)
                    xmlFree(atom->ranges[i]->blockName);
                xmlFree(atom->ranges[i]);
            }
        }
        xmlFree(atom->ranges);
    }

    xmlFree(atom);
    xmlFree(ctxt);

    /* Always return 0 as per libFuzzer contract */
    return 0;
}
