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
// // xmlDoc *
// //xmlParseEntity(const char *filename) {
// //    return(xmlSAXParseEntity(NULL, filename));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlSAXParseEntity(xmlSAXHandler * sax, const char * filename);
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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* Header that declares xmlSAXParseEntity (from the project) */
#include "/src/libxml2/include/libxml/parser.h"

/*
 * Fuzzer entry point
 * This driver writes the fuzzer input to a temporary file and calls:
 *     xmlDoc * xmlSAXParseEntity(xmlSAXHandler * sax, const char * filename);
 *
 * We use the default SAX handler (pass NULL) and free/cleanup any
 * resources returned by the library.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Create a temporary file to hold the input (xml parser expects a filename). */
    char tmpname[] = "/tmp/libxml_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        return 0;
    }

    /* Write the fuzzer data to the temporary file (handle partial writes). */
    size_t remaining = Size;
    const uint8_t *ptr = Data;
    while (remaining > 0) {
        ssize_t w = write(fd, ptr, remaining);
        if (w <= 0) {
            /* Write error - stop writing and continue (parser may still read partial file). */
            break;
        }
        ptr += w;
        remaining -= (size_t)w;
    }

    /* Ensure data is flushed and close the file descriptor. */
    fsync(fd);
    close(fd);

    /* Initialize libxml parser library (safe to call multiple times). */
    xmlInitParser();

    /* Call the targeted function. Pass NULL to use default SAX callbacks. */
    xmlDocPtr doc = xmlSAXParseEntity(NULL, tmpname);

    /* Free the returned document if any. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Cleanup libxml global state that may have been allocated. */
    xmlCleanupParser();

    /* Remove the temporary file. */
    remove(tmpname);

    return 0;
}
