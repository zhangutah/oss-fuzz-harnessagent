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
// //xmlSAXParseFile(xmlSAXHandler *sax, const char *filename,
// //                          int recovery) {
// //    return(xmlSAXParseFileWithData(sax,filename,recovery,NULL));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlSAXParseFileWithData(xmlSAXHandler * sax, const char * filename, int recovery, void * data);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* Use the project-provided header for the symbol */
#include "/src/libxml2/include/libxml/parser.h"

/* Initialize/cleanup libxml parser once for the lifetime of the fuzzer process */
static void libxml_init(void) __attribute__((constructor));
static void libxml_fini(void) __attribute__((destructor));

static void libxml_init(void) {
    /* Initialize the library and check potential global state setup. */
    xmlInitParser();
}

static void libxml_fini(void) {
    /* Cleanup global parser state at process exit. */
    xmlCleanupParser();
    /* Optionally dump memory for debugging (no-op if not enabled) */
#if defined(LIBXML_DEBUG_ENABLED) || defined(LIBXML_MEMORY_ENABLED)
    xmlMemoryDump();
#endif
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Create a temporary file for the parser to read from.
       mkstemp requires a modifiable string. */
    char tmpname[] = "/tmp/libxml2_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0) {
        return 0;
    }

    /* Write the fuzzer input to the temporary file. */
    size_t to_write = Size;
    const uint8_t *buf = Data;
    ssize_t wrote = 0;
    while (to_write > 0) {
        ssize_t r = write(fd, buf + wrote, to_write);
        if (r < 0) break;
        wrote += r;
        to_write -= (size_t)r;
    }

    /* Close the file descriptor; parser will open by filename. */
    close(fd);

    /* Call the target API. Use default SAX handler (NULL) and no user data.
       recovery set to 0. */
    xmlDoc *doc = xmlSAXParseFileWithData(NULL, tmpname, 0, NULL);

    /* Free the returned document if any. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Remove the temporary file. */
    unlink(tmpname);

    return 0;
}
