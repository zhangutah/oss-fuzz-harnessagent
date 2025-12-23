#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Forward declare xmlDoc so our stub can compile without extra includes. */
typedef struct _xmlDoc xmlDoc;

#ifdef __cplusplus
extern "C" {
#endif

/* Provide a simple no-op stub for xmllintShell so other translation units
 * (e.g. regexp.o) which reference it will link successfully. */
void xmllintShell(xmlDoc *doc, const char *filename, FILE *output) {
    (void)doc;
    (void)filename;
    (void)output;
}

#ifdef __cplusplus
}
#endif

/*
 * To get access to the static function testSAX and the xmllintState
 * definition we include the original source file directly into this
 * translation unit. We avoid clashing with its main() by renaming it
 * prior to inclusion.
 *
 * The path below matches the location discovered in the repository.
 */
#define main xmllint_original_main
#include "/src/libxml2/xmllint.c"
#undef main

/* Fuzzer entry point expected by libFuzzer */
#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize the libxml2 parser */
    xmlInitParser();

    /* Create a temporary file to hold the fuzzing input */
    char tmpl[] = "/tmp/xmllint_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        /* Couldn't create temp file; clean up parser and exit */
        xmlCleanupParser();
        return 0;
    }

    /* Write input data to the temporary file */
    ssize_t written = 0;
    const uint8_t *buf = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, buf + written, remaining);
        if (w < 0) break;
        written += w;
        remaining -= w;
    }
    /* Ensure data is flushed and file closed */
    fsync(fd);
    close(fd);

    /* Prepare an xmllintState instance (zero-initialized) */
    xmllintState lint;
    memset(&lint, 0, sizeof(lint));

    /* Minimal initialization so testSAX / parsing paths can run */
    lint.errStream = stderr;
    lint.ctxt = xmlNewParserCtxt(); /* may be NULL on OOM */
    lint.defaultResourceLoader = NULL;
    lint.version = 0;
    lint.maxmem = 0;
    lint.callbacks = 0;
    lint.noout = 0;
    lint.repeat = 1;
    lint.parseOptions = 0;
    lint.appOptions = 0;
    lint.maxAmpl = 0;
    lint.nbpaths = 0;
#if HAVE_DECL_MMAP
    lint.memoryData = NULL;
    lint.memorySize = 0;
#endif
#if defined(LIBXML_READER_ENABLED) && defined(LIBXML_PATTERN_ENABLED)
    lint.pattern = NULL;
    lint.patternc = NULL;
    lint.patstream = NULL;
#endif

    /* Call the function under test with the path to the temporary file */
    testSAX(&lint, tmpl);

    /* Cleanup parser context if created */
    if (lint.ctxt != NULL) {
        xmlFreeParserCtxt(lint.ctxt);
        lint.ctxt = NULL;
    }

    /* Remove temporary file */
    unlink(tmpl);

    /* Cleanup libxml global state */
    xmlCleanupParser();

    return 0;
}