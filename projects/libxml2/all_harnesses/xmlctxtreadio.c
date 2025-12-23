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
//     xmlDoc * xmlCtxtReadIO(xmlParserCtxt * ctxt, xmlInputReadCallback ioread, xmlInputCloseCallback ioclose, void * ioctx, const char * URL, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   xmlDoc * xmlCtxtReadIO(xmlParserCtxt * ctxt,
//                          xmlInputReadCallback ioread,
//                          xmlInputCloseCallback ioclose,
//                          void * ioctx,
//                          const char * URL,
//                          const char * encoding,
//                          int options);
//
// Fuzzer entry point:
//   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/tree.h"

// Simple IO context to feed the fuzzer data to libxml2 via callbacks.
typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
    int closed;
} FuzzIOCtx;

// xmlInputReadCallback: read up to 'len' bytes into buffer, return number of bytes read.
static int fuzz_io_read(void *context, char *buffer, int len) {
    if (context == NULL || buffer == NULL || len <= 0) return 0;
    FuzzIOCtx *c = (FuzzIOCtx *)context;
    if (c->pos >= c->size) return 0;
    size_t remaining = c->size - c->pos;
    int toread = (int)((remaining < (size_t)len) ? remaining : (size_t)len);
    memcpy(buffer, c->data + c->pos, (size_t)toread);
    c->pos += (size_t)toread;
    return toread;
}

// xmlInputCloseCallback: mark closed; do NOT free here to avoid double-free race with the harness.
static int fuzz_io_close(void *context) {
    if (context == NULL) return 0;
    FuzzIOCtx *c = (FuzzIOCtx *)context;
    c->closed = 1;
    return 0;
}

// Ensure libxml2 is initialized once per process and cleaned at exit.
static void libxml_init_once(void) {
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        // Suppress generic error output from libxml2 to avoid noisy stderr during fuzzing.
        xmlSetGenericErrorFunc(NULL, NULL);
        // Register cleanup at process exit.
        atexit(xmlCleanupParser);
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize libxml2 once.
    libxml_init_once();

    // Prepare IO context for the data.
    FuzzIOCtx *ctx = (FuzzIOCtx *)malloc(sizeof(FuzzIOCtx));
    if (!ctx) return 0;
    ctx->data = Data;
    ctx->size = Size;
    ctx->pos = 0;
    ctx->closed = 0;

    // Create a parser context. Passing NULL might be allowed by libxml2,
    // but creating an explicit context lets us free it reliably.
    xmlParserCtxt *pctxt = xmlNewParserCtxt();
    if (pctxt == NULL) {
        free(ctx);
        return 0;
    }

    // Call xmlCtxtReadIO with our callbacks.
    // - ctxt: parser context
    // - ioread: fuzz_io_read
    // - ioclose: fuzz_io_close
    // - ioctx: our ctx
    // - URL: a dummy name
    // - encoding: NULL (auto-detect)
    // - options: 0 (default)
    xmlDoc *doc = xmlCtxtReadIO(pctxt, fuzz_io_read, fuzz_io_close, (void *)ctx, "fuzz://input", NULL, 0);

    // If a document was created, free it.
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    // Free parser context.
    xmlFreeParserCtxt(pctxt);

    // Free our IO context. The close callback only marks closed, it does not free.
    free(ctx);

    return 0;
}
