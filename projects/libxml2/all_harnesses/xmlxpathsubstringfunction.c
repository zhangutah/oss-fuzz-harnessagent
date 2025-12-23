#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Use the project headers found for the symbol. */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/xpathInternals.h"

/*
 Fuzz driver for:
     void xmlXPathSubstringFunction(xmlXPathParserContext *ctxt, int nargs);

 This driver maps input bytes to:
  - nargs: either 2 or 3 (first input byte LSB decides)
  - a string argument (copied from input)
  - a start number (constructed from up to 8 bytes following the string)
  - an optional length number (if nargs == 3), constructed from bytes after start

 The stack order for the parser context must be:
   push string
   push start (number)
   push len (number) [only if nargs == 3]
 so that xmlXPathSubstringFunction will pop them in the expected order.
*/

/* Helper to make a double from up to 8 bytes, consuming bytes from Data */
static void make_double_from_data(const uint8_t *Data, size_t Size, size_t *pos, double *out) {
    uint8_t buf[8] = {0};
    size_t i;
    for (i = 0; i < 8 && *pos < Size; i++, (*pos)++) {
        buf[i] = Data[*pos];
    }
    /* Interpret the 8 bytes as a uint64_t bit pattern and copy into double. */
    uint64_t bits = 0;
    for (i = 0; i < 8; i++) {
        bits |= ((uint64_t)buf[i]) << (8 * i);
    }
    /* Use memcpy to avoid strict aliasing and to place the bitpattern into the double */
    memcpy(out, &bits, sizeof(bits));
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    size_t pos = 0;

    /* Decide nargs: 2 or 3 */
    int nargs = 2;
    if (pos < Size) {
        nargs = 2 + (Data[pos++] & 1);
    }

    /* Initialize libxml2 parser environment */
    xmlInitParser();

    /* Create an XPath evaluation context (document-less) */
    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(NULL);
    if (xpathCtx == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Create a parser context; expression string can be empty */
    xmlXPathParserContextPtr pctxt = xmlXPathNewParserContext((const xmlChar *)"", xpathCtx);
    if (pctxt == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlCleanupParser();
        return 0;
    }

    /* Determine how many bytes remain for constructing args */
    size_t remaining = (pos < Size) ? (Size - pos) : 0;

    /* Split remaining bytes: allocate as follows:
       - string gets roughly half (at least 0)
       - start number gets up to 8 bytes
       - len number gets up to 8 bytes (if needed)
    */
    size_t strLen = 0;
    if (remaining > 0) {
        if (nargs == 3) {
            /* Reserve up to 8+8 = 16 bytes for numbers if possible */
            if (remaining > 16)
                strLen = remaining - 16;
            else
                strLen = (remaining > 8) ? (remaining - 8) : 0;
        } else {
            /* Reserve up to 8 bytes for start number */
            if (remaining > 8)
                strLen = remaining - 8;
            else
                strLen = 0;
        }
    }

    /* Ensure we don't exceed available */
    if (strLen > remaining)
        strLen = remaining;

    /* Build string argument */
    char *strBuf = NULL;
    if (strLen > 0) {
        strBuf = (char *)malloc(strLen + 1);
        if (strBuf == NULL) goto cleanup;
        memcpy(strBuf, Data + pos, strLen);
        strBuf[strLen] = '\0';
    } else {
        /* If no bytes reserved for string, create a short string from next byte or empty */
        if (pos < Size) {
            strBuf = (char *)malloc(2);
            if (strBuf == NULL) goto cleanup;
            strBuf[0] = (char)Data[pos];
            strBuf[1] = '\0';
            /* we used one byte */
            strLen = 1;
        } else {
            strBuf = (char *)malloc(1);
            if (strBuf == NULL) goto cleanup;
            strBuf[0] = '\0';
            strLen = 0;
        }
    }
    pos += strLen;
    if (pos > Size) pos = Size;

    /* Create and push the string object first (so it becomes the bottom-most of the three) */
    xmlXPathObjectPtr strObj = xmlXPathNewCString(strBuf);
    if (strObj == NULL) goto cleanup;
    if (xmlXPathValuePush(pctxt, strObj) == -1) {
        /* push failed, free created object and exit gracefully */
        xmlXPathFreeObject(strObj);
        goto cleanup;
    }

    /* Build start number */
    double startVal = 0.0;
    make_double_from_data(Data, Size, &pos, &startVal);
    xmlXPathObjectPtr startObj = xmlXPathNewFloat(startVal);
    if (startObj == NULL) goto cleanup;
    if (xmlXPathValuePush(pctxt, startObj) == -1) {
        xmlXPathFreeObject(startObj);
        goto cleanup;
    }

    /* If nargs == 3, build len and push it last */
    xmlXPathObjectPtr lenObj = NULL;
    if (nargs == 3) {
        double lenVal = 0.0;
        make_double_from_data(Data, Size, &pos, &lenVal);
        lenObj = xmlXPathNewFloat(lenVal);
        if (lenObj == NULL) goto cleanup;
        if (xmlXPathValuePush(pctxt, lenObj) == -1) {
            xmlXPathFreeObject(lenObj);
            goto cleanup;
        }
    }

    /*
      Now call the target function under test. The parser context (pctxt)
      has the arguments pushed in the expected order:
        bottom -> string, start, [len] <- top
    */
    xmlXPathSubstringFunction(pctxt, nargs);

    /* After the call, there may be objects left on the parser stack.
       Free the parser context which will release any remaining objects. */

cleanup:
    if (strBuf) {
        free(strBuf);
        strBuf = NULL;
    }

    if (pctxt)
        xmlXPathFreeParserContext(pctxt);
    if (xpathCtx)
        xmlXPathFreeContext(xpathCtx);

    /* Cleanup libxml2 global state */
    xmlCleanupParser();

    return 0;
}
