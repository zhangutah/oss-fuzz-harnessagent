#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Include the implementation that contains the target function so the static
 * xmllintShellRegisterNamespace is available in this translation unit.
 *
 * This path is relative to the fuzz/ directory in the project tree.
 */
#include "../shell.c"

/*
 * Fuzzer entry point expected by libFuzzer.
 * We convert Data into a NUL-terminated string and call the target function.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Prepare a NUL-terminated string from input bytes */
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    if (Size > 0) memcpy(buf, Data, Size);
    buf[Size] = '\0';

    /* Setup a minimal xmllintShellCtxt */
    xmllintShellCtxt ctxt;
    memset(&ctxt, 0, sizeof(ctxt));

    /*
     * Create a real XPath context so xmlXPathRegisterNs (used by
     * xmllintShellRegisterNamespace) has a valid context pointer.
     * Passing NULL here yields a context with no associated document but
     * is sufficient for registering namespace prefixes.
     */
#ifdef LIBXML_XPATH_ENABLED
    ctxt.pctxt = xmlXPathNewContext(NULL);
#else
    ctxt.pctxt = NULL;
#endif
    ctxt.output = stdout;

    /* Call the function under test. node and node2 are not used by it. */
    (void)xmllintShellRegisterNamespace(&ctxt, buf, NULL, NULL);

#ifdef LIBXML_XPATH_ENABLED
    if (ctxt.pctxt)
        xmlXPathFreeContext(ctxt.pctxt);
#endif

    free(buf);
    return 0;
}
