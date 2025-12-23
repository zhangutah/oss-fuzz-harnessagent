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
// //xmllintShellLoad(xmllintShellCtxtPtr ctxt, char *filename,
// //             xmlNodePtr node ATTRIBUTE_UNUSED,
// //             xmlNodePtr node2 ATTRIBUTE_UNUSED)
// //{
// //    xmlDocPtr doc;
// //    int html = 0;
// //
// //    if ((ctxt == NULL) || (filename == NULL)) return(-1);
// //    if (ctxt->doc != NULL)
// //        html = (ctxt->doc->type == XML_HTML_DOCUMENT_NODE);
// //
// //    if (html) {
// //#ifdef LIBXML_HTML_ENABLED
// //        doc = htmlParseFile(filename, NULL);
// //#else
// //        fprintf(ctxt->output, "HTML support not compiled in\n");
// //        doc = NULL;
// //#endif /* LIBXML_HTML_ENABLED */
// //    } else {
// //        doc = xmlReadFile(filename,NULL,0);
// //    }
// //    if (doc != NULL) {
// //        if (ctxt->loaded == 1) {
// //            xmlFreeDoc(ctxt->doc);
// //        }
// //        ctxt->loaded = 1;
// //#ifdef LIBXML_XPATH_ENABLED
// //        xmlXPathFreeContext(ctxt->pctxt);
// //#endif /* LIBXML_XPATH_ENABLED */
// //        xmlFree(ctxt->filename);
// //        ctxt->doc = doc;
// //        ctxt->node = (xmlNodePtr) doc;
// //#ifdef LIBXML_XPATH_ENABLED
// //        ctxt->pctxt = xmlXPathNewContext(doc);
// //#endif /* LIBXML_XPATH_ENABLED */
// //        ctxt->filename = (char *) xmlCanonicPath((xmlChar *) filename);
// //    } else
// //        return (-1);
// //    return (0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlReadFile(const char * URL, const char * encoding, int options);
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
#include <sys/stat.h>
#include <sys/types.h>

/* Use the project's header for the function under test. */
#include "/src/libxml2/include/libxml/parser.h"

/*
 Fuzz driver for:
     xmlDoc * xmlReadFile(const char * URL, const char * encoding, int options);

 Strategy:
 - Write the fuzzer input bytes to a temporary file.
 - Derive an encoding string (or NULL) and an integer "options" from the input bytes.
 - Call xmlReadFile() with that filename, encoding and options.
 - Free the returned document (if any) and clean up.
 - Remove the temporary file.
*/

static int write_all(int fd, const uint8_t *buf, size_t size) {
    size_t written = 0;
    while (written < size) {
        ssize_t n = write(fd, buf + written, size - written);
        if (n <= 0) return -1;
        written += (size_t)n;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Create a temporary file to hold the XML content. */
    char tmpl[] = "/tmp/libxml_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return 0;

    /* Write the input bytes to the temp file. It's okay if Size == 0. */
    if (Size > 0) {
        if (write_all(fd, Data, Size) != 0) {
            close(fd);
            unlink(tmpl);
            return 0;
        }
    }

    /* Ensure data is flushed to disk for libraries that read via stdio. */
    fsync(fd);
    close(fd);

    /* Derive encoding (NULL or a short string) from input bytes.
       - If Size < 2 -> encoding = NULL.
       - Else use Data[1] to pick length (0..15). If length == 0, encoding = NULL.
       - Otherwise build a small ascii encoding name from the bytes.
    */
    char *encoding = NULL;
    if (Size >= 2) {
        size_t enc_len = (size_t)(Data[1] & 0x0F); /* 0..15 */
        if (enc_len > 0) {
            encoding = (char *)malloc(enc_len + 1);
            if (encoding == NULL) {
                unlink(tmpl);
                return 0;
            }
            /* Fill with lowercase letters derived from input bytes (wrap if needed). */
            for (size_t i = 0; i < enc_len; ++i) {
                uint8_t b = Data[(2 + i) % Size];
                encoding[i] = (char)('a' + (b % 26));
            }
            encoding[enc_len] = '\0';
        }
    }

    /* Derive options integer from last up to 4 bytes of the input.
       If Size == 0 use 0.
    */
    unsigned int options = 0;
    if (Size > 0) {
        /* Build a 32-bit value from up to 4 trailing bytes to get a varied options value. */
        for (size_t i = 0; i < 4; ++i) {
            size_t idx = (Size > i) ? (Size - 1 - i) : 0;
            uint8_t b = Data[idx % Size];
            options = (options << 8) | b;
        }
    } else {
        options = 0;
    }

    /* Initialize the parser (no-op if already initialized). */
    xmlInitParser();

    /* Suppress libxml error output to stderr to keep fuzzer output clean. */
    xmlSetGenericErrorFunc(NULL, NULL);

    /* Call the target function. */
    xmlDocPtr doc = xmlReadFile(tmpl, encoding, (int)options);

    /* If a document was returned, free it. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Free allocated encoding string if any. */
    if (encoding != NULL) free(encoding);

    /* Remove the temporary file. */
    unlink(tmpl);

    /*
      Note: xmlCleanupParser() is intentionally not called here on every run because
      it can free global state that might be reused across iterations in some
      fuzzers. If you want to ensure maximum cleanup between runs, you may call
      xmlCleanupParser() here, but it's generally recommended only at process exit.
    */

    return 0;
}
