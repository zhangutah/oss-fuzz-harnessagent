#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlerror.h>
#include <libxml/valid.h> /* for xmlFreeElementContent */

#ifdef __cplusplus
extern "C" {
#endif

/* Ensure ATTRIBUTE_UNUSED is defined safely for this translation unit.
   Some environments define ATTRIBUTE_UNUSED as a function-like macro which
   can cause parse errors when used as a trailing token in parameter lists.
   Undefine any prior definition and redefine to a no-op. */
#ifdef ATTRIBUTE_UNUSED
#  undef ATTRIBUTE_UNUSED
#endif
#define ATTRIBUTE_UNUSED

/* Optional fuzzer init: initialize libxml parser subsystem.
   Keep the function signature unchanged. */
int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    xmlInitParser();
    /* suppress default error output to avoid spamming stderr during fuzzing */
    xmlSetGenericErrorFunc(NULL, NULL);
    return 0;
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Prepare a null-terminated xmlChar buffer ensured to start with '(' because
       xmlParseElementContentDecl expects an opening '('. We'll prepend '(' and
       append a NUL. Copy as many bytes of Data as will fit. */
    size_t bufSize = Size + 2; /* '(' + data + '\0' */
    unsigned char *buf = (unsigned char *)malloc(bufSize);
    if (buf == NULL)
        return 0;

    buf[0] = '(';
    /* copy up to Size bytes of Data after the '(' */
    memcpy(buf + 1, Data, Size);
    buf[1 + Size] = 0; /* null-terminate */

    /* Create a new parser context from the memory buffer. This initializes the
       context and pushes the buffer as the input, avoiding the need to call
       internal static functions like xmlCtxtInitializeLate. */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt((const char *)buf, (int)(1 + Size));
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /* Prepare a dummy element name. The parser uses this only for error messages
       and some checks, it need not match the input content. */
    const xmlChar *elemName = (const xmlChar *)"fuzzElem";

    xmlElementContent *result = NULL;

    /* Call the target function. xmlCreateMemoryParserCtxt already set the current
       input appropriately. */
    (void)xmlParseElementContentDecl(ctxt, elemName, &result);

    /* The result, if any, is an internal structure. The parser itself often frees
       it by calling xmlFreeDocElementContent when appropriate. Free it here to
       avoid leaks. xmlFreeElementContent calls xmlFreeDocElementContent(NULL, cur)
       which is safe to use without a document pointer. */
    if (result != NULL) {
        xmlFreeElementContent(result);
        result = NULL;
    }

    /* Free parser context (which also frees the pushed input). */
    xmlFreeParserCtxt(ctxt);

    free(buf);
    return 0;
}

#ifdef __cplusplus
}
#endif