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
// // static xmlDocPtr
// //parseHtml(xmllintState *lint, const char *filename) {
// //    xmlParserCtxtPtr ctxt = lint->ctxt;
// //    xmlDocPtr doc;
// //
// //#ifdef LIBXML_PUSH_ENABLED
// //    if (lint->appOptions & XML_LINT_PUSH_ENABLED) {
// //        FILE *f;
// //        int res;
// //        char chars[4096];
// //
// //        if ((filename[0] == '-') && (filename[1] == 0)) {
// //            f = stdin;
// //        } else {
// //	    f = fopen(filename, "rb");
// //            if (f == NULL) {
// //                fprintf(lint->errStream, "Can't open %s\n", filename);
// //                lint->progresult = XMLLINT_ERR_RDFILE;
// //                return(NULL);
// //            }
// //        }
// //
// //        while ((res = fread(chars, 1, 4096, f)) > 0) {
// //            htmlParseChunk(ctxt, chars, res, 0);
// //        }
// //        htmlParseChunk(ctxt, chars, 0, 1);
// //        doc = xmlCtxtGetDocument(ctxt);
// //
// //        if (f != stdin)
// //            fclose(f);
// //
// //        return(doc);
// //    }
// //#endif /* LIBXML_PUSH_ENABLED */
// //
// //#if HAVE_DECL_MMAP
// //    if (lint->appOptions & XML_LINT_MEMORY) {
// //        xmlParserInputPtr input;
// //
// //        input = xmlNewInputFromMemory(filename,
// //                                      lint->memoryData, lint->memorySize,
// //                                      XML_INPUT_BUF_STATIC);
// //        if (input == NULL) {
// //            lint->progresult = XMLLINT_ERR_MEM;
// //            return(NULL);
// //        }
// //        doc = htmlCtxtParseDocument(ctxt, input);
// //        return(doc);
// //    }
// //#endif
// //
// //    if (strcmp(filename, "-") == 0)
// //        doc = htmlCtxtReadFd(ctxt, STDIN_FILENO, "-", NULL,
// //                             lint->htmlOptions);
// //    else
// //        doc = htmlCtxtReadFile(ctxt, filename, NULL, lint->htmlOptions);
// //
// //    return(doc);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * htmlCtxtReadFd(xmlParserCtxt * ctxt, int fd, const char * URL, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlDoc * htmlCtxtReadFd(xmlParserCtxt * ctxt, int fd,
//                                          const char * URL, const char * encoding, int options);
//
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver:
// - initializes the libxml HTML parser once
// - creates an HTML parser context
// - writes the fuzzer input into a pipe
// - passes the read-end fd to htmlCtxtReadFd
// - frees resources and returns
//
// Note: adjust includes if your build environment requires different include paths.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Include libxml HTML parser header. If your build uses a different include path,
// change this to <libxml/HTMLparser.h> as needed.
#include "/src/libxml2/include/libxml/HTMLparser.h"
#include <libxml/parser.h>
#include <libxml/tree.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /*
         * Initialize the libxml2 parser library. This is safe to call multiple
         * times; we only do it once here.
         */
        xmlInitParser();
        inited = 1;
    }

    if (Data == NULL || Size == 0) {
        /* Allow the parser to exercise empty input as well */
        // Create an empty pipe anyway
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return 0;
    }

    int read_fd = pipefd[0];
    int write_fd = pipefd[1];

    /* Write the fuzzer data into the write end of the pipe, handling partial writes. */
    size_t to_write = Size;
    const uint8_t *ptr = Data;
    while (to_write > 0) {
        ssize_t w = write(write_fd, ptr, to_write > SSIZE_MAX ? SSIZE_MAX : (ssize_t)to_write);
        if (w < 0) {
            if (errno == EINTR) continue;
            break;
        }
        to_write -= (size_t)w;
        ptr += w;
    }

    /* Close write end to signal EOF to the reader */
    close(write_fd);

    /* Create an HTML parser context */
    htmlParserCtxtPtr ctxt = htmlNewParserCtxt();
    if (ctxt == NULL) {
        close(read_fd);
        return 0;
    }

    /* Call the function under test.
       Pass NULL for URL and encoding, and 0 for options. */
    xmlDocPtr doc = htmlCtxtReadFd((xmlParserCtxt *)ctxt, read_fd, NULL, NULL, 0);

    /* Close the read end after parsing */
    close(read_fd);

    /* Free the parsed document if any */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Free the parser context */
    xmlFreeParserCtxt((xmlParserCtxtPtr)ctxt);

    /* Do not call xmlCleanupParser() here: it would destroy global state that
       the fuzzer may rely on across invocations. */

    return 0;
}
