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
// // int
// //xmlVRaiseError(xmlStructuredErrorFunc schannel,
// //               xmlGenericErrorFunc channel, void *data, void *ctx,
// //               xmlNode *node, int domain, int code, xmlErrorLevel level,
// //               const char *file, int line, const char *str1,
// //               const char *str2, const char *str3, int int1, int col,
// //               const char *msg, va_list ap)
// //{
// //    xmlParserCtxtPtr ctxt = NULL;
// //    /* xmlLastError is a macro retrieving the per-thread global. */
// //    xmlErrorPtr lastError = xmlGetLastErrorInternal();
// //    xmlErrorPtr to = lastError;
// //
// //    if (code == XML_ERR_OK)
// //        return(0);
// //#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
// //    if (code == XML_ERR_INTERNAL_ERROR)
// //        xmlAbort("Unexpected internal error: %s\n", msg);
// //#endif
// //    if ((xmlGetWarningsDefaultValue == 0) && (level == XML_ERR_WARNING))
// //        return(0);
// //
// //    if ((domain == XML_FROM_PARSER) || (domain == XML_FROM_HTML) ||
// //        (domain == XML_FROM_DTD) || (domain == XML_FROM_NAMESPACE) ||
// //	(domain == XML_FROM_IO) || (domain == XML_FROM_VALID)) {
// //	ctxt = (xmlParserCtxtPtr) ctx;
// //
// //        if (ctxt != NULL)
// //            to = &ctxt->lastError;
// //    }
// //
// //    if (xmlVUpdateError(to, ctxt, node, domain, code, level, file, line,
// //                        str1, str2, str3, int1, col, msg, ap))
// //        return(-1);
// //
// //    if (to != lastError) {
// //        if (xmlCopyError(to, lastError) < 0)
// //            return(-1);
// //    }
// //
// //    if (schannel != NULL) {
// //	schannel(data, to);
// //    } else if (xmlStructuredError != NULL) {
// //        xmlStructuredError(xmlStructuredErrorContext, to);
// //    } else if (channel != NULL) {
// //        /* Don't invoke legacy error handlers */
// //        if ((channel == xmlGenericErrorDefaultFunc) ||
// //            (channel == xmlParserError) ||
// //            (channel == xmlParserWarning) ||
// //            (channel == xmlParserValidityError) ||
// //            (channel == xmlParserValidityWarning))
// //            xmlFormatError(to, xmlGenericError, xmlGenericErrorContext);
// //        else
// //	    channel(data, "%s", to->message);
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
//     void xmlFormatError(const xmlError * err, xmlGenericErrorFunc channel, void * data);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

/* Include the libxml2 error definitions from the project */
#include "/src/libxml2/include/libxml/xmlerror.h"

/*
 * A simple xmlGenericErrorFunc implementation that writes formatted
 * messages to the provided FILE* (ctx).
 */
static void fuzz_channel(void *ctx, const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    if (ctx != NULL) {
        vfprintf((FILE *)ctx, msg, ap);
    } else {
        /* Fallback to stderr if no ctx provided */
        vfprintf(stderr, msg, ap);
    }
    va_end(ap);
}

/* Helper: allocate and copy a slice of input data into a NUL-terminated string.
 * Caps the allocation to max_len for safety.
 */
static char *alloc_string_from_slice(const uint8_t *data, size_t len, size_t max_len) {
    if (len == 0) {
        /* create a minimal non-empty string */
        char *s = (char *)malloc(2);
        if (!s) return NULL;
        s[0] = 'A';
        s[1] = '\0';
        return s;
    }
    if (len > max_len) len = max_len;
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, data, len);
    s[len] = '\0';
    return s;
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) {
        /* Nothing to do */
        return 0;
    }

    /* Prepare an xmlError instance, zeroed first */
    xmlError err;
    memset(&err, 0, sizeof(err));

    /* Use small caps on string allocations to avoid excessive memory use */
    const size_t MAX_STR = 4096;

    /* We'll split the input buffer into a few slices to populate string fields */
    size_t off = 0;
    size_t remaining = Size;

    size_t part_count = 5; /* message, file, str1, str2, str3 */
    size_t base_part = remaining / part_count;
    size_t rem = remaining % part_count;

    /* Determine sizes for each part (distribute remainder to first parts) */
    size_t part_sizes[5];
    for (size_t i = 0; i < 5; i++) {
        part_sizes[i] = base_part + (i < rem ? 1 : 0);
    }

    /* Ensure at least 1 byte for message to avoid NULL message */
    if (part_sizes[0] == 0) part_sizes[0] = 1;

    /* Cap individual parts */
    for (size_t i = 0; i < 5; i++) {
        if (part_sizes[i] > MAX_STR) part_sizes[i] = MAX_STR;
    }

    /* message */
    size_t take = part_sizes[0];
    if (take > remaining) take = remaining;
    err.message = alloc_string_from_slice(Data + off, take, MAX_STR);
    off += take;
    remaining = (off <= Size) ? (Size - off) : 0;

    /* file */
    take = part_sizes[1];
    if (take > remaining) take = remaining;
    err.file = alloc_string_from_slice(Data + off, take, MAX_STR);
    off += take;
    remaining = (off <= Size) ? (Size - off) : 0;

    /* str1 */
    take = part_sizes[2];
    if (take > remaining) take = remaining;
    err.str1 = alloc_string_from_slice(Data + off, take, MAX_STR);
    off += take;
    remaining = (off <= Size) ? (Size - off) : 0;

    /* str2 */
    take = part_sizes[3];
    if (take > remaining) take = remaining;
    err.str2 = alloc_string_from_slice(Data + off, take, MAX_STR);
    off += take;
    remaining = (off <= Size) ? (Size - off) : 0;

    /* str3 */
    take = part_sizes[4];
    if (take > remaining) take = remaining;
    err.str3 = alloc_string_from_slice(Data + off, take, MAX_STR);
    off += take;
    remaining = (off <= Size) ? (Size - off) : 0;

    /* Use some bytes (if available) to set numeric fields. If not available, use defaults. */
    size_t idx = 0;
    /* domain (int) */
    if (Size > idx) {
        err.domain = (int)Data[idx++];
    } else {
        err.domain = XML_FROM_NONE;
    }
    /* code (int) - ensure non-zero to avoid xmlFormatError early return */
    if (Size > idx) {
        err.code = (int)Data[idx++];
        if (err.code == XML_ERR_OK) err.code = XML_ERR_INTERNAL_ERROR;
    } else {
        err.code = XML_ERR_INTERNAL_ERROR;
    }
    /* level (xmlErrorLevel) */
    if (Size > idx) {
        err.level = (xmlErrorLevel)(Data[idx++] % 4); /* 0..3 */
    } else {
        err.level = XML_ERR_ERROR;
    }
    /* line (int) */
    if (Size > idx) {
        /* combine up to 4 bytes for a line number */
        unsigned int v = 0;
        unsigned int shift = 0;
        for (int i = 0; i < 4 && (Size > idx); i++) {
            v |= ((unsigned int)Data[idx++]) << shift;
            shift += 8;
        }
        err.line = (int)(v & 0x7FFFFFFF);
    } else {
        err.line = 0;
    }
    /* int1 and int2 */
    if (Size > idx) {
        err.int1 = (int)Data[idx++];
    } else {
        err.int1 = 0;
    }
    if (Size > idx) {
        err.int2 = (int)Data[idx++];
    } else {
        err.int2 = 0;
    }

    /* ctxt and node: keep NULL to avoid dereferencing unknown memory inside xmlFormatError */
    err.ctxt = NULL;
    err.node = NULL;

    /* Call the target function. Use stdout as the channel context so the fuzz driver
     * forwards output to the fuzzer logs or console.
     */
    xmlFormatError(&err, (xmlGenericErrorFunc)fuzz_channel, (void *)stdout);

    /* Free allocated strings */
    if (err.message) free(err.message);
    if (err.file) free(err.file);
    if (err.str1) free(err.str1);
    if (err.str2) free(err.str2);
    if (err.str3) free(err.str3);

    return 0;
}
