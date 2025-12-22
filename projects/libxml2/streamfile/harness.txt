#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Include the xmllint implementation so static streamFile() is available.
// Using the absolute path found in the project.
#include "/src/libxml2/xmllint.c"

/*
 * xmllintShell is defined in shell.c in the project, but the shell.c file
 * is not part of this fuzzing translation unit. The xmllint.c implementation
 * references xmllintShell (e.g., parseAndPrintFile -> xmllintShell), so we
 * provide a minimal stub here to satisfy the linker.
 *
 * The real shell implementation prints or dumps a document; for fuzzing we
 * don't need that behavior, just a no-op that accepts the same arguments.
 *
 * The xmlDoc type is declared in libxml2 headers; forward-declare here to
 * avoid pulling extra headers.
 */
typedef struct _xmlDoc xmlDoc;
void xmllintShell(xmlDoc *doc, const char *filename, FILE *output) {
    (void)doc;
    (void)filename;
    (void)output;
    /* no-op stub for fuzzing */
}

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create a temporary file and write Data to it.
    char tmpname[] = "/tmp/libxml2_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) return 0;

    if (Size > 0) {
        ssize_t written = write(fd, Data, Size);
        (void)written; // ignore partial write for fuzzing
    }
    close(fd);

    // Initialize an xmllintState with minimal sensible defaults.
    // xmllintState is defined in xmllint.c (included above).
    xmllintState lint_state;
    memset(&lint_state, 0, sizeof(lint_state));

    // Use stderr for error output so libxml2 messages are visible in logs.
    lint_state.errStream = stderr;
    // Basic defaults used by streamFile
    lint_state.parseOptions = 0;
    lint_state.maxAmpl = 0;
    lint_state.repeat = 1;
    lint_state.progresult = 0;
    lint_state.nbpaths = 0;
#if HAVE_DECL_MMAP
    lint_state.memoryData = NULL;
    lint_state.memorySize = 0;
#endif

    // Initialize libxml2 parser state (safe to call multiple times).
    xmlInitParser();

    // Call the target function with the temporary file path.
    // streamFile is available because we included xmllint.c.
    streamFile(&lint_state, tmpname);

    // Clean up parser state.
    xmlCleanupParser();

    // Remove the temporary file.
    unlink(tmpname);

    return 0;
}
