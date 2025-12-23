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
// //xmlParse3986Query(xmlURIPtr uri, const char **str)
// //{
// //    const char *cur;
// //
// //    cur = *str;
// //
// //    while ((ISA_PCHAR(uri, cur)) || (*cur == '/') || (*cur == '?'))
// //        NEXT(cur);
// //    if (uri != NULL) {
// //        if (uri->query != NULL)
// //            xmlFree(uri->query);
// //	if (uri->cleanup & XML_URI_NO_UNESCAPE)
// //	    uri->query = STRNDUP(*str, cur - *str);
// //	else
// //	    uri->query = xmlURIUnescapeString(*str, cur - *str, NULL);
// //        if (uri->query == NULL)
// //            return (-1);
// //
// //	/* Save the raw bytes of the query as well.
// //	 * See: http://mail.gnome.org/archives/xml/2007-April/thread.html#00114
// //	 */
// //	if (uri->query_raw != NULL)
// //	    xmlFree (uri->query_raw);
// //	uri->query_raw = STRNDUP (*str, cur - *str);
// //        if (uri->query_raw == NULL)
// //            return (-1);
// //    }
// //    *str = cur;
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
//     char * xmlURIUnescapeString(const char * str, int len, char * target);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

/* Include the libxml2 headers (use absolute paths from the workspace) */
#include "/src/libxml2/include/libxml/uri.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 Fuzzer entry point for xmlURIUnescapeString(const char * str, int len, char * target);

 Strategy:
 - Call the function once letting it allocate the result (target == NULL).
 - Then call it with a provided target buffer to exercise that code path.
 - Clamp very large input sizes to a reasonable bound to avoid OOM or extremely long runs.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Clamp size to a sane maximum for fuzzing to avoid excessive allocations */
    const size_t MAX_LEN = 1000000; /* 1MB */
    int len = (Size > MAX_LEN) ? (int)MAX_LEN : (int)Size;

    /* Call with target == NULL so xmlURIUnescapeString will allocate via xmlMalloc */
    char *result = xmlURIUnescapeString((const char *)Data, len, NULL);
    if (result) {
        /* Free allocation via libxml's free API */
        xmlFree(result);
    }

    /* Call with a provided target buffer to exercise that path.
       Allocate (len + 1) bytes for safety (function writes a terminating NUL). */
    char *buf = (char *)malloc((size_t)len + 1);
    if (buf != NULL) {
        /* It's safe to pass the raw Data pointer as str and buf as target */
        char *ret2 = xmlURIUnescapeString((const char *)Data, len, buf);
        /* When target != NULL, the function returns the provided target (buf).
           Free buf with free(). */
        (void)ret2; /* silence unused variable warnings in some builds */
        free(buf);
    }

    return 0;
}
