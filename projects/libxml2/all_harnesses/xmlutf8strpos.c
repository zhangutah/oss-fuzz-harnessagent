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
//     const xmlChar * xmlUTF8Strpos(const xmlChar * utf, int pos);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Auto-generated libFuzzer driver for: const xmlChar * xmlUTF8Strpos(const xmlChar * utf, int pos);
// Uses Data to provide both the UTF-8 buffer and the position argument.
//
// Build note (example):
//   clang -g -O1 -fsanitize=fuzzer,address,undefined -I/src/libxml2/include \
//         fuzzer_xmlUTF8Strpos.c /path/to/libxml2.a -o fuzzer_xmlUTF8Strpos
//
// Header path is project-absolute as discovered.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "/src/libxml2/include/libxml/xmlstring.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    // Copy input into a NUL-terminated buffer so xmlUTF8Strpos can safely read it.
    // We'll use the first 4 bytes (if present) to derive the `pos` argument,
    // and the remainder as the UTF-8 string to search.
    uint8_t *buf = (uint8_t *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = 0; // ensure NUL-terminated

    const xmlChar *utf;
    int pos = 0;

    if (Size >= 4) {
        // Extract 4 bytes as little-endian unsigned integer, then reinterpret as signed int
        uint32_t p = (uint32_t)Data[0]
                   | ((uint32_t)Data[1] << 8)
                   | ((uint32_t)Data[2] << 16)
                   | ((uint32_t)Data[3] << 24);
        pos = (int)p;
        // Use remainder of buffer as the string
        utf = (const xmlChar *)(buf + 4);
    } else {
        // Not enough bytes for pos; use pos = 0 and whole buffer as string
        pos = 0;
        utf = (const xmlChar *)buf;
    }

    // Call the target function. It returns a pointer into the string or NULL.
    const xmlChar *res = xmlUTF8Strpos(utf, pos);

    // Touch the result in a benign way to avoid it being optimized away.
    // Do not dereference if NULL.
    if (res != NULL) {
        volatile unsigned char c = res[0];
        (void)c;
    }

    free(buf);
    return 0;
}
