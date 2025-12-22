#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

#include <libxml/parser.h>
#include <libxml/relaxng.h>

/* Silently ignore errors/warnings to reduce noise during fuzzing. */
static void
silent_relaxng_error(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

static void
silent_relaxng_warning(void *ctx, const char *msg, ...)
{
    (void)ctx;
    (void)msg;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Limit Size to INT_MAX to satisfy xmlRelaxNGNewMemParserCtxt signature. */
    if (Size > (size_t)INT_MAX)
        Size = (size_t)INT_MAX;

    /* Make a null-terminated copy of the input for safety. */
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Initialize the parser library once. This is cheap and idempotent. */
    xmlInitParser();

#ifdef LIBXML_RELAXNG_ENABLED
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewMemParserCtxt(buf, (int)Size);
    if (pctxt != NULL) {
        /* Suppress parser error/warning output to keep fuzzer logs clean. */
        xmlRelaxNGSetParserErrors(pctxt,
                                  (xmlRelaxNGValidityErrorFunc)silent_relaxng_error,
                                  (xmlRelaxNGValidityWarningFunc)silent_relaxng_warning,
                                  NULL);

        /* Parse the Relax-NG schema provided by the fuzzer input. */
        xmlRelaxNGPtr schema = xmlRelaxNGParse(pctxt);

        /* If a schema was produced, free it. */
        if (schema != NULL) {
            xmlRelaxNGFree(schema);
        }

        /* Free the parser context. */
        xmlRelaxNGFreeParserCtxt(pctxt);
    }
#else
    /* If Relax-NG support isn't compiled in, do nothing. */
    (void)buf;
    (void)Size;
#endif

    free(buf);

    /* Do not call xmlCleanupParser() here: it's usually called at program exit.
       Repeated cleanup / init across fuzzing iterations can be unsafe/expensive. */

    return 0;
}
