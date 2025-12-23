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
// //htmlParseFile(const char *filename, const char *encoding) {
// //    return(htmlSAXParseFile(filename, encoding, NULL, NULL));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * htmlSAXParseFile(const char * filename, const char * encoding, htmlSAXHandler * sax, void * userData);
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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Include the html parser header found in the project */
#include "/src/libxml2/include/libxml/HTMLparser.h"

/* Fuzzer entry point expected by libFuzzer/LLVMFuzzer:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int xml_inited = 0;
    if (!xml_inited) {
        /* Initialize the libxml2 parser once. Do not call xmlCleanupParser()
           here because the fuzzer runs many iterations in the same process. */
        xmlInitParser();
        xml_inited = 1;
    }

    /* create a temporary filename to write the fuzz input to; htmlSAXParseFile
       expects a filename, not a memory buffer. */
    char tmpl[] = "/tmp/libxml_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    /* Write the input bytes to the temporary file. */
    if (Size > 0) {
        ssize_t wrote = write(fd, Data, Size);
        (void)wrote; /* ignore short-write for fuzzing harness */
    }
    close(fd);

    /* Call the target function. Pass NULL for encoding and sax handler to use
       default behavior. userData is NULL. */
    xmlDocPtr doc = htmlSAXParseFile(tmpl, NULL, NULL, NULL);

    /* Free any returned document to avoid leaks across iterations. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Remove the temporary file. */
    unlink(tmpl);

    return 0;
}