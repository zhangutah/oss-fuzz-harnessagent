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
//     int xmlSAXUserParseFile(xmlSAXHandler * sax, void * user_data, const char * filename);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Use the header found for xmlSAXUserParseFile */
#include "/src/libxml2/include/libxml/parser.h"

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

static void ensure_libxml_initialized(void) {
    static int inited = 0;
    if (!inited) {
        xmlInitParser();
        /* optional: disable network/entity loading to reduce external effects */
        xmlLoadExtDtdDefaultValue = 0;
        inited = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    ensure_libxml_initialized();

    /* create a temporary file for the fuzzer input */
    char tmpl[] = "/tmp/fuzz_xml_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return 0;

    /* write the fuzz data to the file */
    ssize_t to_write = (ssize_t)Size;
    const uint8_t *ptr = Data;
    while (to_write > 0) {
        ssize_t w = write(fd, ptr, (size_t)to_write);
        if (w <= 0) break;
        to_write -= w;
        ptr += w;
    }
    /* close descriptor so parser can open by name */
    close(fd);

    /* Call the target function. Pass NULL for sax and user_data to use defaults. */
    /* xmlSAXUserParseFile returns an int status; ignore it for fuzzing. */
    xmlSAXUserParseFile(NULL, NULL, tmpl);

    /* remove temporary file */
    unlink(tmpl);

    /* Do not call xmlCleanupParser() here: avoid tearing down global state between fuzz iterations. */

    return 0;
}