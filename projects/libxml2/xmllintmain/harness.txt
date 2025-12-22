// Generate a fuzz driver based the given function signature in C language. Output the full driver code in reply.
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// // Example 1:
// 
// // int
// //main(int argc, char **argv) {
// //    return(xmllintMain(argc, (const char **) argv, stderr, NULL));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmllintMain(int argc, const char ** argv, FILE * errStream, xmlResourceLoader loader);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmllintMain(int argc, const char ** argv, FILE * errStream, xmlResourceLoader loader);
// Generated fuzz entry: LLVMFuzzerTestOneInput
//
// This driver writes the fuzzer input to a temporary file and invokes xmllintMain
// with the temporary filename as argument. It attempts minimal cleanup between runs.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

// Include the xmllint private header discovered in the project.
// Using the absolute path as returned by the symbol header lookup.
#include "/src/libxml2/include/private/lint.h"

// libxml parser cleanup
#include <libxml/parser.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Create a temporary file to hold the fuzz input
    // Template must be mutable for mkstemp
    char tmpname[] = "/tmp/xmllint_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzer data to the temp file
    ssize_t total_written = 0;
    const uint8_t *buf = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, buf + total_written, remaining);
        if (w <= 0) {
            // On interruption, try again; otherwise break
            if (errno == EINTR)
                continue;
            break;
        }
        total_written += w;
        remaining -= (size_t)w;
    }

    // Ensure data is flushed and close the file descriptor
    fsync(fd);
    close(fd);

    // Build argv: program name + filename
    const char *argv[3];
    argv[0] = "xmllint";
    argv[1] = tmpname;
    argv[2] = NULL;

    // Call xmllintMain. Pass stderr for error output and NULL for the resource loader.
    // xmllintMain is expected to return an int status; ignore it for the fuzzer harness.
    // Protect against unexpected failures inside xmllintMain as best effort (it should not exit the process).
    (void)xmllintMain(2, argv, stderr, NULL);

    // Remove temporary file
    unlink(tmpname);

    // Clean up libxml parser global state between runs
    xmlCleanupParser();

    return 0;
}
