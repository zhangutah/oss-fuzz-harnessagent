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
//     xmlDoc * htmlReadFile(const char * URL, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

/* Use the header path discovered for htmlReadFile */
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include <libxml/parser.h> /* for xmlInitParser, xmlFreeDoc, etc. */

/*
 * Fuzzing entry point for libFuzzer / LLVMFuzzer.
 *
 * This driver writes the input blob to a temporary file and calls:
 *     xmlDoc * htmlReadFile(const char * URL, const char * encoding, int options);
 *
 * It then frees the returned document (if any) and unlinks the temp file.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser once (not thread-safe initialization, but adequate for fuzz driver) */
    static int libxml_inited = 0;
    if (!libxml_inited) {
        xmlInitParser();
        libxml_inited = 1;
    }

    /* Create a temporary file to store the input data */
    char tmpl[] = "/tmp/libxml_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    /* Write all bytes (including NULs) to the file */
    const uint8_t *p = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, p, remaining);
        if (w <= 0) {
            /* write error: abort writing and proceed to cleanup */
            break;
        }
        remaining -= (size_t)w;
        p += w;
    }
    close(fd);

    /* Derive encoding and options from the input to exercise different codepaths */
    const char *encoding = NULL;
    int options = 0;

    /* Simple heuristics:
     * - If first byte is odd => try "UTF-8", else NULL (let parser guess).
     * - Use second byte (if present) as a small options value.
     */
    if (Size >= 1) {
        if (Data[0] % 2 == 1) {
            encoding = "UTF-8";
        } else {
            encoding = NULL;
        }
    }
    if (Size >= 2) {
        options = (int)Data[1];
    }

    /* Call the target function */
    xmlDocPtr doc = htmlReadFile(tmpl, encoding, options);

    /* Free doc if returned */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Remove temporary file */
    unlink(tmpl);

    /* Do not call xmlCleanupParser() per-input (expensive & may affect fuzzing); OS will cleanup at process exit. */

    return 0;
}
