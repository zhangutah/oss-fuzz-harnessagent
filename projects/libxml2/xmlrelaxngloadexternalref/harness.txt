#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

/*
 * Include the implementation directly so the static helper
 * xmlRelaxNGLoadExternalRef is available to the fuzzer.
 *
 * Note: adjust the path below if your build system places the
 * source somewhere else. The absolute path below matches the
 * repository layout used to generate this driver.
 */
#include "/src/libxml2/relaxng.c"

/*
 * Fuzzer entry point.
 *
 * This harness writes the fuzzer input to a temporary file and passes
 * that filename as the "URL" argument to xmlRelaxNGLoadExternalRef.
 * The fuzzer input is also provided as the in-memory buffer for the
 * parser context (xmlRelaxNGNewMemParserCtxt) so the fuzzer data is
 * actually used during parsing.
 *
 * We create a parser context via xmlRelaxNGNewMemParserCtxt so the
 * function has a valid ctxt to operate on. After the call we free
 * the parser context which should cleanup any allocated resources.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int initialized = 0;
    if (!initialized) {
        /* initialize libxml global state once per process */
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0)
        return 0;

    /* Create a temporary file and dump the fuzzer data there. */
    char tmpl[] = "/tmp/fuzz_relaxng_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1)
        return 0;

    /* Write all input bytes to the file. */
    ssize_t written = write(fd, Data, Size);
    (void)written; /* ignore partial write in this simple harness */

    /* Close the file descriptor - xmlRelaxReadFile will open it by name. */
    close(fd);

    /* Create a parser context using the fuzzer input as the in-memory buffer */
    int sizeArg = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    xmlRelaxNGParserCtxtPtr ctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, sizeArg);
    if (ctxt == NULL) {
        unlink(tmpl);
        return 0;
    }

    /* Prepare URL param: pass the temp filename as xmlChar* */
    const xmlChar *URL = (const xmlChar *)tmpl;

    /* Prepare ns param: use up to the first 64 bytes of the input as a C string */
    xmlChar *ns = NULL;
    size_t nslen = (Size < 64) ? Size : 64;
    if (nslen > 0) {
        ns = (xmlChar *)malloc(nslen + 1);
        if (ns != NULL) {
            memcpy(ns, Data, nslen);
            ns[nslen] = '\0';
        }
    }

    /* Call the target function. It's static in relaxng.c, but available
     * because we included that C file above.
     *
     * We ignore the return value; the parser ctxt free should clean up
     * registered documents.
     */
    (void) xmlRelaxNGLoadExternalRef(ctxt, URL, ns);

    /* Cleanup */
    xmlRelaxNGFreeParserCtxt(ctxt);

    if (ns != NULL)
        free(ns);

    /* Remove the temporary file */
    unlink(tmpl);

    /* Do not call xmlCleanupParser() here to avoid tearing down global
     * state while the fuzzer process continues to run.
     */

    return 0;
}
