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
// //schemasOneTest(const char *sch,
// //               const char *filename,
// //               const char *err,
// //	       int options,
// //	       xmlSchemaPtr schemas) {
// //    int ret = 0;
// //    int i;
// //    int parseErrorsSize = testErrorsSize;
// //
// //    /*
// //     * Test both memory and streaming validation.
// //     */
// //    for (i = 0; i < 2; i++) {
// //        xmlSchemaValidCtxtPtr ctxt;
// //        int validResult = 0;
// //
// //        testErrorsSize = parseErrorsSize;
// //        testErrors[parseErrorsSize] = 0;
// //
// //        if (schemas == NULL)
// //            goto done;
// //
// //        ctxt = xmlSchemaNewValidCtxt(schemas);
// //        xmlSchemaSetValidStructuredErrors(ctxt, testStructuredErrorHandler,
// //                                          NULL);
// //
// //        if (i == 0) {
// //            xmlDocPtr doc;
// //
// //            doc = xmlReadFile(filename, NULL, options);
// //            if (doc == NULL) {
// //                fprintf(stderr, "failed to parse instance %s for %s\n", filename, sch);
// //                return(-1);
// //            }
// //            validResult = xmlSchemaValidateDoc(ctxt, doc);
// //            xmlFreeDoc(doc);
// //        } else {
// //            validResult = xmlSchemaValidateFile(ctxt, filename, options);
// //        }
// //
// //        if (validResult == 0) {
// //            testErrorHandler(NULL, "%s validates\n", filename);
// //        } else if (validResult > 0) {
// //            testErrorHandler(NULL, "%s fails to validate\n", filename);
// //        } else {
// //            testErrorHandler(NULL, "%s validation generated an internal "
// //                             "error\n", filename);
// //        }
// //
// //        xmlSchemaFreeValidCtxt(ctxt);
// //
// //done:
// //        if (compareFileMem(err, testErrors, testErrorsSize)) {
// //            fprintf(stderr, "Error for %s on %s failed\n", filename, sch);
// //            ret = 1;
// //        }
// //    }
// //
// //    return(ret);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlSchemaValidateFile(xmlSchemaValidCtxt * ctxt, const char * filename, int options);
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

/* Use the project header found for the symbol */
#include "/src/libxml2/include/libxml/xmlschemas.h"

/*
 * Fuzzer entry point.
 * Writes the fuzzer input to a temporary file and calls:
 *   int xmlSchemaValidateFile(xmlSchemaValidCtxt * ctxt, const char * filename, int options);
 *
 * We create a validation context with xmlSchemaNewValidCtxt(NULL).
 * If the context is created successfully we call xmlSchemaValidateFile on the temp file.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Create a temporary file to hold the fuzz input */
    char tmpname[] = "/tmp/libxml_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd < 0)
        return 0;

    /* Write the data to the temporary file */
    ssize_t written = 0;
    const uint8_t *ptr = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, ptr, remaining);
        if (w <= 0)
            break;
        written += w;
        ptr += w;
        remaining -= w;
    }
    /* Ensure data is flushed and close file descriptor */
    fsync(fd);
    close(fd);

    /* Initialize libxml2 parser environment */
    xmlInitParser();

    /* Create a validation context. Passing NULL schema (we don't load an XSD).
       Some implementations may return NULL or a usable context. Check result
       before calling the validation function. */
    xmlSchema *schema = NULL;
    xmlSchemaValidCtxt *vctxt = xmlSchemaNewValidCtxt(schema);
    if (vctxt != NULL) {
        /* Inform the context about the filename (optional, but useful). */
        xmlSchemaValidateSetFilename(vctxt, tmpname);

        /* Call the function under test. Use options = 0 for default behavior. */
        (void)xmlSchemaValidateFile(vctxt, tmpname, 0);

        /* Free the validation context */
        xmlSchemaFreeValidCtxt(vctxt);
    }

    /* Cleanup */
    unlink(tmpname);
    xmlCleanupParser();

    return 0;
}
