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
// //xmlXPathTranslateFunction(xmlXPathParserContext *ctxt, int nargs) {
// //    xmlXPathObjectPtr str = NULL;
// //    xmlXPathObjectPtr from = NULL;
// //    xmlXPathObjectPtr to = NULL;
// //    xmlBufPtr target;
// //    int offset, max;
// //    int ch;
// //    const xmlChar *point;
// //    xmlChar *cptr, *content;
// //
// //    CHECK_ARITY(3);
// //
// //    CAST_TO_STRING;
// //    to = xmlXPathValuePop(ctxt);
// //    CAST_TO_STRING;
// //    from = xmlXPathValuePop(ctxt);
// //    CAST_TO_STRING;
// //    str = xmlXPathValuePop(ctxt);
// //    if (ctxt->error != 0)
// //        goto error;
// //
// //    /*
// //     * Account for quadratic runtime
// //     */
// //    if (ctxt->context->opLimit != 0) {
// //        unsigned long f1 = xmlStrlen(from->stringval);
// //        unsigned long f2 = xmlStrlen(str->stringval);
// //
// //        if ((f1 > 0) && (f2 > 0)) {
// //            unsigned long p;
// //
// //            f1 = f1 / 10 + 1;
// //            f2 = f2 / 10 + 1;
// //            p = f1 > ULONG_MAX / f2 ? ULONG_MAX : f1 * f2;
// //            if (xmlXPathCheckOpLimit(ctxt, p) < 0)
// //                goto error;
// //        }
// //    }
// //
// //    target = xmlBufCreate(50);
// //    if (target == NULL) {
// //        xmlXPathPErrMemory(ctxt);
// //        goto error;
// //    }
// //
// //    max = xmlUTF8Strlen(to->stringval);
// //    for (cptr = str->stringval; (ch=*cptr); ) {
// //        offset = xmlUTF8Strloc(from->stringval, cptr);
// //        if (offset >= 0) {
// //            if (offset < max) {
// //                point = xmlUTF8Strpos(to->stringval, offset);
// //                if (point)
// //                    xmlBufAdd(target, point, xmlUTF8Strsize(point, 1));
// //            }
// //        } else
// //            xmlBufAdd(target, cptr, xmlUTF8Strsize(cptr, 1));
// //
// //        /* Step to next character in input */
// //        cptr++;
// //        if ( ch & 0x80 ) {
// //            /* if not simple ascii, verify proper format */
// //            if ( (ch & 0xc0) != 0xc0 ) {
// //                xmlXPathErr(ctxt, XPATH_INVALID_CHAR_ERROR);
// //                break;
// //            }
// //            /* then skip over remaining bytes for this char */
// //            while ( (ch <<= 1) & 0x80 )
// //                if ( (*cptr++ & 0xc0) != 0x80 ) {
// //                    xmlXPathErr(ctxt, XPATH_INVALID_CHAR_ERROR);
// //                    break;
// //                }
// //            if (ch & 0x80) /* must have had error encountered */
// //                break;
// //        }
// //    }
// //
// //    content = xmlBufDetach(target);
// //    if (content == NULL)
// //        xmlXPathPErrMemory(ctxt);
// //    else
// //        xmlXPathValuePush(ctxt, xmlXPathCacheWrapString(ctxt, content));
// //    xmlBufFree(target);
// //error:
// //    xmlXPathReleaseObject(ctxt->context, str);
// //    xmlXPathReleaseObject(ctxt->context, from);
// //    xmlXPathReleaseObject(ctxt->context, to);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlUTF8Strloc(const xmlChar * utf, const xmlChar * utfchar);
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
#include <limits.h>

/* Include the header that declares xmlUTF8Strloc and xmlChar */
#include "/src/libxml2/include/libxml/xmlstring.h"

/*
 Fuzz driver for:
   int xmlUTF8Strloc(const xmlChar * utf, const xmlChar * utfchar);

 Strategy:
 - Split the input Data into two non-empty parts (utfchar and utf).
 - Null-terminate both parts and call xmlUTF8Strloc.
 - Free allocated buffers and return 0 (libFuzzer convention).
 - Cap the processed input size to avoid huge allocations.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Prevent excessive allocation from very large inputs */
    const size_t MAX_PROCESS = 1 << 20; /* 1 MiB */
    size_t len = Size > MAX_PROCESS ? MAX_PROCESS : Size;
    if (len < 2) /* need at least 1 byte for utfchar and 1 byte for utf */
        return 0;

    /* Choose a split so both parts are at least 1 byte long */
    size_t split = 1 + (Data[0] % (len - 1)); /* 1 .. len-1 */

    size_t utfchar_len = split;
    size_t utf_len = len - split;

    /* Allocate and copy utfchar (pattern) */
    xmlChar *utfchar = (xmlChar *)malloc(utfchar_len + 1);
    if (utfchar == NULL) return 0;
    memcpy(utfchar, Data, utfchar_len);
    utfchar[utfchar_len] = (xmlChar)0;

    /* Allocate and copy utf (haystack) */
    xmlChar *utf = (xmlChar *)malloc(utf_len + 1);
    if (utf == NULL) {
        free(utfchar);
        return 0;
    }
    memcpy(utf, Data + split, utf_len);
    utf[utf_len] = (xmlChar)0;

    /* Call the target function. Feed both orders to exercise behavior. */
    (void)xmlUTF8Strloc(utf, utfchar);
    (void)xmlUTF8Strloc(utfchar, utf);

    free(utf);
    free(utfchar);

    return 0;
}
