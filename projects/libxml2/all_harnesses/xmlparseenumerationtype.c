#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Project headers (absolute paths discovered in the workspace) */
#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/valid.h"

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize libxml2 global state (no-op if already done). */
    xmlInitParser();

    /* Create a new parser context */
    xmlParserCtxt *ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Ensure we have a non-NULL pointer for xmlParserInputBufferCreateMem.
     * If Size == 0, pass an empty string. Casting Data (uint8_t*) to char* is OK
     * because the API expects a const char* memory block. */
    const char *mem = (Size > 0 && Data != NULL) ? (const char *)Data : "";
    int mem_size = (Size > 0 && Data != NULL) ? (int)Size : 0;

    /* Create an input buffer from the fuzz data */
    xmlParserInputBuffer *buf = xmlParserInputBufferCreateMem(mem, mem_size, XML_CHAR_ENCODING_NONE);
    xmlParserInput *input = NULL;
    if (buf != NULL) {
        /* Create an input stream from the buffer. xmlNewIOInputStream will
         * attach the buffer to the returned input (ownership transferred to
         * the xmlParserInput). */
        input = xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE);
        if (input == NULL) {
            /* xmlNewIOInputStream failed, so free the buffer ourselves. */
            xmlFreeParserInputBuffer(buf);
            buf = NULL;
        }
    }

    if (input != NULL) {
        /* Properly push the input into the parser context so that
         * xmlFreeParserCtxt will pop and free it. */
        if (xmlCtxtPushInput(ctxt, input) < 0) {
            /* Push failed: free the input (which also frees its buffer). */
            xmlFreeInputStream(input);
            input = NULL;
        }
    } else {
        /* If creating an input failed, proceed with the context anyway;
         * the target function should handle errors and return safely. */
    }

    /* Call the target function under test */
    xmlEnumeration *res = xmlParseEnumerationType(ctxt);

    /* Free result if any */
    if (res != NULL) {
        xmlFreeEnumeration(res);
    }

    /* Free parser context (this will pop/free any pushed inputs) */
    xmlFreeParserCtxt(ctxt);

    /* Cleanup libxml2 global state (safe to call). */
    xmlCleanupParser();

    return 0;
}
