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
// // void
// //xmlXPathSubstringFunction(xmlXPathParserContext *ctxt, int nargs) {
// //    xmlXPathObjectPtr str, start, len;
// //    double le=0, in;
// //    int i = 1, j = INT_MAX;
// //
// //    if (nargs < 2) {
// //	CHECK_ARITY(2);
// //    }
// //    if (nargs > 3) {
// //	CHECK_ARITY(3);
// //    }
// //    /*
// //     * take care of possible last (position) argument
// //    */
// //    if (nargs == 3) {
// //	CAST_TO_NUMBER;
// //	CHECK_TYPE(XPATH_NUMBER);
// //	len = xmlXPathValuePop(ctxt);
// //	le = len->floatval;
// //	xmlXPathReleaseObject(ctxt->context, len);
// //    }
// //
// //    CAST_TO_NUMBER;
// //    CHECK_TYPE(XPATH_NUMBER);
// //    start = xmlXPathValuePop(ctxt);
// //    in = start->floatval;
// //    xmlXPathReleaseObject(ctxt->context, start);
// //    CAST_TO_STRING;
// //    CHECK_TYPE(XPATH_STRING);
// //    str = xmlXPathValuePop(ctxt);
// //
// //    if (!(in < INT_MAX)) { /* Logical NOT to handle NaNs */
// //        i = INT_MAX;
// //    } else if (in >= 1.0) {
// //        i = (int)in;
// //        if (in - floor(in) >= 0.5)
// //            i += 1;
// //    }
// //
// //    if (nargs == 3) {
// //        double rin, rle, end;
// //
// //        rin = floor(in);
// //        if (in - rin >= 0.5)
// //            rin += 1.0;
// //
// //        rle = floor(le);
// //        if (le - rle >= 0.5)
// //            rle += 1.0;
// //
// //        end = rin + rle;
// //        if (!(end >= 1.0)) { /* Logical NOT to handle NaNs */
// //            j = 1;
// //        } else if (end < INT_MAX) {
// //            j = (int)end;
// //        }
// //    }
// //
// //    i -= 1;
// //    j -= 1;
// //
// //    if ((i < j) && (i < xmlUTF8Strlen(str->stringval))) {
// //        xmlChar *ret = xmlUTF8Strsub(str->stringval, i, j - i);
// //        if (ret == NULL)
// //            xmlXPathPErrMemory(ctxt);
// //	xmlXPathValuePush(ctxt, xmlXPathCacheNewString(ctxt, ret));
// //	xmlFree(ret);
// //    } else {
// //	xmlXPathValuePush(ctxt, xmlXPathCacheNewCString(ctxt, ""));
// //    }
// //
// //    xmlXPathReleaseObject(ctxt->context, str);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlUTF8Strlen(const xmlChar * utf);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Include the header that declares xmlUTF8Strlen.
   Using the absolute project header path discovered in the workspace.
   If you integrate this driver into a build system, you may prefer:
     #include <libxml/xmlstring.h>
   or adjust include paths accordingly.
*/
#include "/src/libxml2/include/libxml/xmlstring.h"

/* Fuzzer entry point expected by libFuzzer/LLVMFuzzer.
   This driver makes a NUL-terminated copy of the input and calls xmlUTF8Strlen.
   If Size == 0 it also calls xmlUTF8Strlen(NULL) to exercise that code path.
*/
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive: if Data is NULL, nothing to do. */
    if (Data == NULL) {
        /* Exercise the NULL path */
        xmlUTF8Strlen(NULL);
        return 0;
    }

    if (Size == 0) {
        /* Call with NULL when there's no data to better exercise behavior. */
        xmlUTF8Strlen(NULL);
        return 0;
    }

    /* Allocate a buffer one byte larger to ensure NUL termination. */
    uint8_t *buf = (uint8_t *)malloc(Size + 1);
    if (buf == NULL) {
        return 0;
    }

    memcpy(buf, Data, Size);
    buf[Size] = 0; /* NUL-terminate */

    /* Call the target function. Cast to the expected xmlChar const pointer. */
    (void)xmlUTF8Strlen((const xmlChar *)buf);

    free(buf);
    return 0;
}

/* Optional standalone harness for local testing (not used by libFuzzer).
   Compile normally and run: ./fuzz_driver input.bin
*/
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        perror("fseek");
        return 1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        perror("ftell");
        return 1;
    }
    rewind(f);

    uint8_t *data = (uint8_t *)malloc((size_t)sz);
    if (!data) {
        fclose(f);
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    size_t read = fread(data, 1, (size_t)sz, f);
    fclose(f);

    LLVMFuzzerTestOneInput(data, read);
    free(data);
    return 0;
}
#endif