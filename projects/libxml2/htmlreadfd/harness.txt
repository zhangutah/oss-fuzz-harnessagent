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
//     xmlDoc * htmlReadFd(int fd, const char * URL, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Use the project header discovered for htmlReadFd */
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include <libxml/parser.h> /* for xmlInitParser, xmlCleanupParser, xmlFreeDoc */

/*
 * Fuzz driver for:
 *   xmlDoc * htmlReadFd(int fd, const char * URL, const char * encoding, int options);
 *
 * Fuzzer entry point:
 *   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
 *
 * Approach:
 * - Write the fuzzer input to a temporary file (tmpfile()).
 * - Rewind and obtain its file descriptor with fileno().
 * - Call htmlReadFd on that fd with NULL URL/encoding and options=0.
 * - Free the returned xmlDoc (if any) and cleanup the parser.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Create a temporary file to hold the fuzzer input */
    FILE *tmp = tmpfile();
    if (!tmp) return 0;

    /* If there's data, write it to the temp file */
    if (Size > 0) {
        size_t written = fwrite(Data, 1, Size, tmp);
        if (written != Size) {
            fclose(tmp);
            return 0;
        }
        /* Ensure data is flushed and seek back to start */
        fflush(tmp);
        if (fseek(tmp, 0, SEEK_SET) != 0) {
            fclose(tmp);
            return 0;
        }
    }

    int fd = fileno(tmp);
    if (fd < 0) {
        fclose(tmp);
        return 0;
    }

    /* Initialize libxml parser state */
    xmlInitParser();

    /* Call the target function. Pass NULL for URL and encoding, options = 0 */
    xmlDocPtr doc = htmlReadFd(fd, NULL, NULL, 0);

    /* Free any returned document */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Cleanup parser state */
    xmlCleanupParser();

    /* Close and remove temporary file */
    fclose(tmp);

    return 0;
}