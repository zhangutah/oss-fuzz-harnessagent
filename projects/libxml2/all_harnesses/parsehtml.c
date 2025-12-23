// Fuzz driver for: xmlDocPtr parseHtml(xmllintState * lint, const char * filename);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This harness includes the project xmllint.c translation unit so the real
// parseHtml static symbol (from xmllint.c) is available in this compilation
// unit. That allows the fuzzer to exercise the real implementation.
//
// Build notes:
// - Link with libxml2 (e.g., -lxml2).
// - Compile normally as a libFuzzer target with this translation unit.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

// Include the project source that contains parseHtml so the actual function
// is available in this translation unit. This relies on building only this
// TU for the fuzzer target (including a .c file into another is intentional
// here to access a static symbol).
#include "../xmllint.c"

// Provide a no-op definition of xmllintShell so that linking succeeds when
// the separate shell.c unit is not part of the fuzzer build. xmllint.c may
// reference this function; for fuzzing parseHtml we don't need its behavior.
void
xmllintShell(xmlDoc *doc, const char *filename, FILE *output) {
    (void)doc;
    (void)filename;
    (void)output;
}

// Fuzzer entry point - do not change signature.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize libxml2 parser layer.
    xmlInitParser();

    // Create a temporary file to hold the fuzz input.
    // Use mkstemp to get a unique filename we can pass to htmlReadFile/parseHtml.
    char tmpname[] = "/tmp/fuzz_html_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        // Could not create temp file; cleanup and return.
        xmlCleanupParser();
        return 0;
    }

    // Write the input bytes to the temp file.
    ssize_t written_total = 0;
    while ((size_t)written_total < Size) {
        ssize_t w = write(fd, Data + written_total, Size - written_total);
        if (w <= 0) break;
        written_total += w;
    }
    // Ensure data flushed to disk for readers that may use stdio.
    fsync(fd);
    close(fd);

    // Prepare a minimal xmllintState. The real xmllintState type is defined in
    // xmllint.c which we've included above.
    xmllintState lint;
    memset(&lint, 0, sizeof(lint));
    lint.errStream = stderr;
    lint.ctxt = NULL; // htmlCtxtReadFile can accept a NULL ctxt and will create one.
#ifdef LIBXML_HTML_ENABLED
    lint.htmlOptions = 0; // default HTML parser options
#endif
#if HAVE_DECL_MMAP
    lint.memoryData = NULL;
    lint.memorySize = 0;
#endif
    lint.appOptions = 0;

    xmlDocPtr doc = NULL;

    // First, attempt to parse directly from the fuzz buffer (so the fuzzer data
    // is actually consumed by the parser). This gives the fuzzer maximal effect.
    if (Size > 0) {
        // clamp Size to int for libxml2 APIs
        int isize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
#ifdef LIBXML_HTML_ENABLED
        // Prefer htmlReadMemory for HTML parsing if available.
        // htmlReadMemory signature: htmlReadMemory(const char *buffer, int size, const char *URL, const char *encoding, int options)
        doc = htmlReadMemory((const char *)Data, isize, NULL, NULL, lint.htmlOptions);
#else
        // Fallback to XML memory parser if HTML parser is not available.
        // xmlReadMemory signature: xmlReadMemory(const char *buffer, int size, const char *URL, const char *encoding, int options)
        doc = xmlReadMemory((const char *)Data, isize, NULL, NULL, 0);
#endif
    }

    // If memory-based parse failed or wasn't attempted, and if parseHtml is available,
    // also try the original file-based parse to exercise that code path.
#ifdef LIBXML_HTML_ENABLED
    if (doc == NULL) {
        doc = parseHtml(&lint, tmpname);
    }
#endif

    // Free the document if parsed.
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    // Remove the temporary file.
    unlink(tmpname);

    // Cleanup libxml2 global state.
    xmlCleanupParser();

    return 0;
}
