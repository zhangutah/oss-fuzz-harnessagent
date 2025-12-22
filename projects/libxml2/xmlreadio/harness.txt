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
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlReadIO(xmlInputReadCallback ioread, xmlInputCloseCallback ioclose, void * ioctx, const char * URL, const char * encoding, int options);
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

#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

/*
 Fuzz driver for:
   xmlDoc * xmlReadIO(xmlInputReadCallback ioread,
                      xmlInputCloseCallback ioclose,
                      void * ioctx,
                      const char * URL,
                      const char * encoding,
                      int options);

 We implement a simple xmlInputReadCallback that feeds the fuzzer bytes
 to libxml2, and an xmlInputCloseCallback that frees the context.
*/

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
} fuzz_io_ctx;

/* xmlInputReadCallback signature:
   int (*xmlInputReadCallback) (void * context, char * buffer, int len);
   Return number of bytes read, 0 on EOF, -1 on error.
*/
static int fuzz_read_cb(void *context, char *buffer, int len) {
    if (context == NULL || buffer == NULL || len <= 0) return -1;
    fuzz_io_ctx *ctx = (fuzz_io_ctx *)context;
    if (ctx->pos >= ctx->size) return 0; /* EOF */

    size_t remaining = ctx->size - ctx->pos;
    size_t want = (size_t)len;
    size_t to_copy = remaining < want ? remaining : want;
    /* guard against very large len (cap to INT_MAX) */
    if (to_copy > (size_t)INT_MAX) to_copy = (size_t)INT_MAX;

    memcpy(buffer, ctx->data + ctx->pos, to_copy);
    ctx->pos += to_copy;
    return (int)to_copy;
}

/* xmlInputCloseCallback signature:
   int (*xmlInputCloseCallback) (void * context);
*/
static int fuzz_close_cb(void *context) {
    if (context == NULL) return -1;
    free(context);
    return 0;
}

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Initialize libxml parser once. Repeated initialization is harmless but
       xmlCleanupParser should not be called between fuzzer inputs. */
    static int libxml_initialized = 0;
    if (!libxml_initialized) {
        xmlInitParser();
        libxml_initialized = 1;
    }

    if (Data == NULL || Size == 0) return 0;

    /* Prepare io context */
    fuzz_io_ctx *ctx = (fuzz_io_ctx *)malloc(sizeof(fuzz_io_ctx));
    if (ctx == NULL) return 0;
    ctx->data = Data;
    ctx->size = Size;
    ctx->pos = 0;

    /* Call xmlReadIO with our callbacks. Pass NULL for URL and encoding, 0 for options. */
    xmlDocPtr doc = xmlReadIO(fuzz_read_cb, fuzz_close_cb, ctx, NULL, NULL, 0);

    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Do not call xmlCleanupParser() here; the fuzzer controls process lifetime. */
    return 0;
}
