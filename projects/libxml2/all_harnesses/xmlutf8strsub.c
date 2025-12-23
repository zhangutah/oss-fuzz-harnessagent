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
//     xmlChar * xmlUTF8Strsub(const xmlChar * utf, int start, int len);
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

/* Use absolute project headers as provided by the project layout */
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzz driver for:
   xmlChar * xmlUTF8Strsub(const xmlChar * utf, int start, int len);

 Fuzzer entry point:
   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* Reserve 8 bytes from the input for two 32-bit integers (start, len)
       if available. The remainder becomes the UTF-8 buffer. */
    const size_t META_BYTES = 8;
    size_t str_len = (Size > META_BYTES) ? (Size - META_BYTES) : Size;

    /* Allocate a NUL-terminated buffer for the utf string to ensure xmlUTF8Strsub
       never reads past the provided data. */
    uint8_t *utfbuf = (uint8_t *)malloc(str_len + 1);
    if (!utfbuf) return 0;
    if (str_len > 0) {
        memcpy(utfbuf, Data, str_len);
    }
    utfbuf[str_len] = 0; /* nul-terminate */

    int start = 0;
    int len = 0;

    if (Size > META_BYTES) {
        /* Parse two 32-bit values from the last 8 bytes of Data.
           We interpret them as little-endian uint32_t and then cast to int32_t
           so negative values are possible and exercised. */
        uint32_t s = 0, l = 0;
        /* copy safely regardless of alignment */
        memcpy(&s, Data + str_len + 0, sizeof(uint32_t));
        memcpy(&l, Data + str_len + 4, sizeof(uint32_t));
        start = (int32_t)s;
        len = (int32_t)l;
    } else if (Size >= 4) {
        /* If we have between 4 and 8 bytes, still try to parse one int for start, leave len=0 */
        uint32_t s = 0;
        memcpy(&s, Data + (Size >= 4 ? Size - 4 : 0), sizeof(uint32_t));
        start = (int32_t)s;
        len = 0;
    } else {
        /* Small inputs: use defaults start=0, len=0 */
        start = 0;
        len = 0;
    }

    /* Call the target function. xmlUTF8Strsub returns a newly allocated xmlChar*
       (or NULL). Free it with xmlFree if non-NULL. */
    xmlChar *res = xmlUTF8Strsub((const xmlChar *)utfbuf, start, len);
    if (res != NULL) {
        /* xmlUTF8Strsub uses libxml allocation functions; free with xmlFree. */
        xmlFree(res);
    }

    free(utfbuf);
    return 0;
}
