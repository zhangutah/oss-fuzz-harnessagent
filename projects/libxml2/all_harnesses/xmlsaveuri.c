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
// //xmlPrintURI(FILE *stream, xmlURI *uri) {
// //    xmlChar *out;
// //
// //    out = xmlSaveUri(uri);
// //    if (out != NULL) {
// //	fprintf(stream, "%s", (char *) out);
// //	xmlFree(out);
// //    }
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlChar * xmlSaveUri(xmlURI * uri);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Project headers (use absolute paths as requested) */
#include "/src/libxml2/include/libxml/uri.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

/*
 Fuzz driver for:
     xmlChar * xmlSaveUri(xmlURI * uri);

 Fuzzer entry point:
     extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
*/

static char *
consume_string(const uint8_t **data, size_t *size) {
    if (*size == 0)
        return NULL;

    /* Use 1 byte length prefix (0..255). Cap each allocation to 1024 bytes. */
    unsigned int len = (*data)[0];
    (*data)++; (*size)--;

    if (len == 0) {
        /* Return an empty string (not NULL) to exercise empty-field behavior */
        char *s = (char *)malloc(1);
        if (s) s[0] = '\0';
        return s;
    }

    if (len > *size)
        len = (unsigned int)*size;
    if (len > 1024)
        len = 1024;

    char *s = (char *)malloc(len + 1);
    if (!s)
        return NULL;
    memcpy(s, *data, len);
    s[len] = '\0';

    *data += len;
    *size -= len;
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    const uint8_t *p = Data;
    size_t left = Size;

    /* Prepare an xmlURI on the stack and zero it to have predictable defaults */
    xmlURI uri;
    memset(&uri, 0, sizeof(uri));
    uri.port = -1;
    uri.cleanup = 0;

    /* Populate fields in a deterministic order using the input bytes.
       For each string field we consume a length byte then that many bytes. */
    uri.scheme = consume_string(&p, &left);
    uri.opaque = consume_string(&p, &left);
    uri.authority = consume_string(&p, &left);
    uri.server = consume_string(&p, &left);
    uri.user = consume_string(&p, &left);
    uri.path = consume_string(&p, &left);
    uri.query = consume_string(&p, &left);
    uri.fragment = consume_string(&p, &left);
    uri.query_raw = consume_string(&p, &left);

    /* If data remains, use up to 2 bytes for port (big-endian), otherwise leave -1 */
    if (left >= 1) {
        /* take 1 or 2 bytes to form a small port number */
        unsigned int port = p[0];
        p++; left--;
        if (left >= 1) {
            port = (port << 8) | p[0];
            p++; left--;
        }
        /* Normalize port into a reasonable range; keep -1 reserved for unspecified */
        uri.port = (int)(port % 65536);
    }

    /* Optionally set cleanup flag if a byte remains */
    if (left >= 1) {
        uri.cleanup = p[0] & 1;
        /* consume the byte */
        p++; left--;
    }

    /* Call the target function under test */
    xmlChar *out = xmlSaveUri(&uri);

    /* Free the returned string if non-NULL using libxml's xmlFree (maps to free) */
    if (out != NULL) {
        xmlFree((void *)out);
    }

    /* Free any allocated input-derived strings. They were allocated with malloc. Use xmlFree
       which is provided by libxml (and typically points to free) to match allocator. */
    if (uri.scheme) xmlFree((void *)uri.scheme);
    if (uri.opaque) xmlFree((void *)uri.opaque);
    if (uri.authority) xmlFree((void *)uri.authority);
    if (uri.server) xmlFree((void *)uri.server);
    if (uri.user) xmlFree((void *)uri.user);
    if (uri.path) xmlFree((void *)uri.path);
    if (uri.query) xmlFree((void *)uri.query);
    if (uri.fragment) xmlFree((void *)uri.fragment);
    if (uri.query_raw) xmlFree((void *)uri.query_raw);

    return 0;
}
