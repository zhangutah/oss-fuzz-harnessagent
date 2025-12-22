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
// // xmlDtd *
// //xmlParseDTD(const xmlChar *publicId, const xmlChar *systemId) {
// //    return(xmlSAXParseDTD(NULL, publicId, systemId));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDtd * xmlSAXParseDTD(xmlSAXHandler * sax, const xmlChar * publicId, const xmlChar * systemId);
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
#include <sys/types.h>
#include <sys/stat.h>

/* Use the header found in the project for the symbol */
#include "/src/libxml2/include/libxml/parser.h"

/*
 Fuzz driver for:
     xmlDtd * xmlSAXParseDTD(xmlSAXHandler * sax, const xmlChar * publicId, const xmlChar * systemId);

 Approach:
 - Write the fuzzer input bytes to a temporary file.
 - Pass the temporary filename as the systemId to xmlSAXParseDTD with sax = NULL
   so the default resolver will load the file and the parser will parse the provided bytes as a DTD.
 - Free the returned DTD (if any) and remove the temporary file.
 - Initialize the parser library before parsing.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Ignore empty inputs */
    if (Data == NULL || Size == 0) return 0;

    /* Create a temporary file to store the fuzzer input */
    char tmpl[] = "/tmp/libxml_dtd_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    /* Write all bytes to the temporary file (binary write) */
    ssize_t written = 0;
    const uint8_t *buf = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, buf + written, remaining);
        if (w <= 0) break;
        written += w;
        remaining -= (size_t)w;
    }
    /* Close the file descriptor */
    close(fd);

    /* Initialize the libxml2 library (safe to call multiple times) */
    xmlInitParser();

    /* Call the target function:
       - sax = NULL to use default SAX handler
       - publicId = NULL
       - systemId = path to the temporary file (as xmlChar *) */
    xmlDtdPtr dtd = xmlSAXParseDTD(NULL, NULL, (const xmlChar *)tmpl);

    /* If a DTD was returned, free it */
    if (dtd != NULL) {
        xmlFreeDtd(dtd);
    }

    /* Remove the temporary file */
    unlink(tmpl);

    /* Note: We intentionally do not call xmlCleanupParser() here because
       the fuzzer runs in a long-lived process and calling cleanup repeatedly
       can be counterproductive. If desired, cleanup can be performed at
       process exit. */

    return 0;
}
