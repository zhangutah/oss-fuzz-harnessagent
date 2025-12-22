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
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlReadFd(int fd, const char * URL, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlDoc * xmlReadFd(int fd, const char * URL, const char * encoding, int options);
// Build-time note: This includes the libxml2 parser header via the absolute path discovered in the workspace.
// If building outside that workspace, replace the include with <libxml/parser.h> or adjust include paths.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "/src/libxml2/include/libxml/parser.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Basic sanity
    if (Data == NULL || Size == 0)
        return 0;

    // Create a temporary file and write the fuzzer input to it.
    // Use mkstemp to safely create a file descriptor suitable for xmlReadFd.
    char tmp_template[] = "/tmp/libxml_fuzzXXXXXX";
    int fd = mkstemp(tmp_template);
    if (fd == -1) {
        return 0;
    }

    // Write all data to the temporary file (handle partial writes).
    const uint8_t *ptr = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, ptr, remaining);
        if (w <= 0) {
            // write failed; cleanup and return
            close(fd);
            unlink(tmp_template);
            return 0;
        }
        remaining -= (size_t)w;
        ptr += w;
    }

    // Rewind file descriptor to start so xmlReadFd reads from beginning.
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        close(fd);
        unlink(tmp_template);
        return 0;
    }

    // Initialize the parser library (optional but recommended).
    xmlInitParser();

    // Call the target function. Use NULL for URL and encoding and 0 for options.
    // Optionally, you may choose specific parse options (e.g., XML_PARSE_NONET) if desired.
    xmlDocPtr doc = xmlReadFd(fd, /* URL */ NULL, /* encoding */ NULL, /* options */ 0);

    // Free the returned document if any.
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    // Perform global cleanup for libxml2.
    xmlCleanupParser();

    // Close and remove the temporary file.
    close(fd);
    unlink(tmp_template);

    return 0;
}