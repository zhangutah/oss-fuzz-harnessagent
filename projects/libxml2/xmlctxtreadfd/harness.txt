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
// // static int
// //fdParseTest(const char *filename, const char *result, const char *err,
// //             int options) {
// //    xmlParserCtxtPtr ctxt;
// //    xmlDocPtr doc;
// //    const char *base = NULL;
// //    int size, res = 0, fd;
// //
// //    nb_tests++;
// //    fd = open(filename, RD_FLAGS);
// //#ifdef LIBXML_HTML_ENABLED
// //    if (options & XML_PARSE_HTML) {
// //        ctxt = htmlNewParserCtxt();
// //        xmlCtxtSetErrorHandler(ctxt, testStructuredErrorHandler, NULL);
// //        doc = htmlCtxtReadFd(ctxt, fd, filename, NULL, options);
// //        htmlFreeParserCtxt(ctxt);
// //    } else
// //#endif
// //    {
// //        ctxt = xmlNewParserCtxt();
// //        xmlCtxtSetErrorHandler(ctxt, testStructuredErrorHandler, NULL);
// //	doc = xmlCtxtReadFd(ctxt, fd, filename, NULL, options);
// //        xmlFreeParserCtxt(ctxt);
// //    }
// //    close(fd);
// //    if (result) {
// //	if (doc == NULL) {
// //	    base = "";
// //	    size = 0;
// //	} else {
// //#ifdef LIBXML_HTML_ENABLED
// //	    if (options & XML_PARSE_HTML) {
// //		htmlDocDumpMemory(doc, (xmlChar **) &base, &size);
// //	    } else
// //#endif
// //	    xmlDocDumpMemory(doc, (xmlChar **) &base, &size);
// //	}
// //	res = compareFileMem(result, base, size);
// //    }
// //    if (doc != NULL) {
// //	if (base != NULL)
// //	    xmlFree((char *)base);
// //	xmlFreeDoc(doc);
// //    }
// //    if (res != 0) {
// //        fprintf(stderr, "Result for %s failed in %s\n", filename, result);
// //        return(-1);
// //    }
// //    if (err != NULL) {
// //	res = compareFileMem(err, testErrors, testErrorsSize);
// //	if (res != 0) {
// //	    fprintf(stderr, "Error for %s failed\n", filename);
// //	    return(-1);
// //	}
// //    } else if (options & XML_PARSE_DTDVALID) {
// //        if (testErrorsSize != 0)
// //	    fprintf(stderr, "Validation for %s failed\n", filename);
// //    }
// //
// //    return(0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlCtxtReadFd(xmlParserCtxt * ctxt, int fd, const char * URL, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlDoc * xmlCtxtReadFd(xmlParserCtxt * ctxt, int fd, const char * URL, const char * encoding, int options);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Note: this driver writes the fuzzer input to a temporary file, opens it, and
// passes the file descriptor to xmlCtxtReadFd. It initializes the libxml2
// parser on first use, cleans up allocated objects, and removes the temp file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

// Include the header that declares xmlCtxtReadFd and related types.
// Using the project absolute path as provided by the workspace.
#include "/src/libxml2/include/libxml/parser.h"

#ifndef LLVMFuzzerTestOneInput
// Provide the fuzzer entry declaration if not already defined by the build.
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
#endif

// Ensure libxml2 is initialized once.
static void ensure_libxml_init(void) {
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) {
        return 0;
    }

    ensure_libxml_init();

    // Create a temporary file to hold the fuzzer input.
    // mkstemp will create and open the file and return a file descriptor.
    char tmpl[] = "/tmp/libxml2_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        return 0;
    }

    // Write all bytes from Data to the temporary file.
    size_t remaining = Size;
    const uint8_t *ptr = Data;
    while (remaining > 0) {
        ssize_t w = write(fd, ptr, remaining);
        if (w <= 0) {
            // write error; clean up and return
            close(fd);
            unlink(tmpl);
            return 0;
        }
        remaining -= (size_t)w;
        ptr += w;
    }

    // Rewind to the beginning so xmlCtxtReadFd reads from start.
    if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Create a new parser context.
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Call the target function. Use NULL for URL and encoding and options = 0.
    // xmlCtxtReadFd will parse the content from the provided file descriptor.
    xmlDocPtr doc = xmlCtxtReadFd(ctxt, fd, NULL, NULL, 0);

    // Free returned document (if any) and the parser context.
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    xmlFreeParserCtxt(ctxt);

    // Clean up the temporary file and descriptor.
    close(fd);
    unlink(tmpl);

    // Do not call xmlCleanupParser() here: calling it repeatedly can interfere
    // with multi-threaded fuzzers or other tests. Library initialization is
    // handled once in ensure_libxml_init().

    return 0;
}
