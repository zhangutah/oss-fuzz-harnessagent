/*
 * Fuzz driver that uses the real parseXml from the libxml2 xmllint.c source.
 *
 * This harness includes the xmllint.c source so the static parseXml function
 * is available in this TU. It writes fuzzer input to a temporary
 * file and calls parseXml(xmllintState *, const char *).
 *
 * Build note: link with libxml2 (e.g., -lxml2).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Include the project's xmllint.c so the static parseXml implementation is
 * available in this TU. The relative path assumes this file lives in
 * fuzz/ and xmllint.c is in the parent directory.
 *
 * Wrap the include in extern "C" when compiled as C++ so that the functions
 * in xmllint.c get C linkage and link correctly.
 */
#ifdef __cplusplus
extern "C" {
#endif
#include "../xmllint.c"
#ifdef __cplusplus
}
#endif

/* Provide a no-op xmllintShell implementation to satisfy references from
 * xmllint.c (parseAndPrintFile calls xmllintShell). The real implementation
 * lives in shell.c which is not linked into the fuzzer build, so provide a
 * stub here.
 */
#ifdef __cplusplus
extern "C" {
#endif
void
xmllintShell(xmlDoc *doc, const char *filename, FILE *output) {
    (void)doc;
    (void)filename;
    (void)output;
    /* intentionally empty for fuzzing harness */
}
#ifdef __cplusplus
}
#endif

/* Fuzzer entry point expected by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser environment */
    xmlInitParser();

    /* Prepare xmllintState (the full struct is provided by xmllint.c) */
    xmllintState lint;
    memset(&lint, 0, sizeof(lint));
    lint.errStream = stderr;
    lint.parseOptions = 0;
    lint.appOptions = 0;
    lint.progresult = 0; /* XMLLINT_RETURN_OK */

    /* Create a new parser context for this input */
    lint.ctxt = xmlNewParserCtxt();
    if (lint.ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Write the fuzzer data to a temporary file and pass its name to parseXml */
    char tmpname[] = "/tmp/xmllint_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        xmlFreeParserCtxt(lint.ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Write the data to the file */
    ssize_t wrote = 0;
    const uint8_t *p = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t res = write(fd, p + wrote, remaining);
        if (res <= 0) break;
        wrote += res;
        remaining -= res;
    }
    /* Ensure data is flushed */
    fsync(fd);
    close(fd);

    /* Call the real parseXml from xmllint.c */
    xmlDocPtr doc = parseXml(&lint, tmpname);

    /* Free the parsed document if any */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Cleanup */
    unlink(tmpname);
    if (lint.ctxt != NULL)
        xmlFreeParserCtxt(lint.ctxt);
    xmlCleanupParser();

    return 0;
}
