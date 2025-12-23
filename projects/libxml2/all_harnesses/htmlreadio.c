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
//     xmlDoc * htmlReadIO(xmlInputReadCallback ioread, xmlInputCloseCallback ioclose, void * ioctx, const char * URL, const char * encoding, int options);
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

/* Prefer the project header found for htmlReadIO */
#include "/src/libxml2/include/libxml/HTMLparser.h"

/*
 * Fuzzer driver for:
 *   xmlDoc * htmlReadIO(xmlInputReadCallback ioread,
 *                       xmlInputCloseCallback ioclose,
 *                       void * ioctx,
 *                       const char * URL,
 *                       const char * encoding,
 *                       int options);
 *
 * This driver implements a simple in-memory ioctx that serves the
 * fuzzer input to the htmlReadIO reader callback.
 */

struct fuzz_io_ctx {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

/* xmlInputReadCallback:
 *   returns number of bytes read into buffer or 0 for EOF, -1 for error.
 */
static int fuzz_ioread(void *context, char *buffer, int len) {
    if (context == NULL || buffer == NULL || len <= 0)
        return -1;

    struct fuzz_io_ctx *c = (struct fuzz_io_ctx *)context;
    if (c->offset >= c->size)
        return 0; /* EOF */

    size_t remaining = c->size - c->offset;
    size_t to_copy = (size_t)len;
    if (to_copy > remaining)
        to_copy = remaining;

    memcpy(buffer, c->data + c->offset, to_copy);
    c->offset += to_copy;
    return (int)to_copy;
}

/* xmlInputCloseCallback:
 *   called when the parser is done. We don't free the context here
 *   because the fuzzer harness will free it after htmlReadIO returns.
 */
static int fuzz_ioclose(void *context) {
    (void)context;
    return 0;
}

/* Fuzzer entry point expected by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser (idempotent) and silence generic errors to avoid noisy output */
    xmlInitParser();
    xmlSetGenericErrorFunc(NULL, NULL);

    /* Prepare IO context pointing to fuzzer data */
    struct fuzz_io_ctx ctx;
    ctx.data = Data;
    ctx.size = Size;
    ctx.offset = 0;

    /* Call htmlReadIO with our callbacks.
     * URL and encoding set to NULL. Options set to 0 (no special flags).
     */
    xmlDocPtr doc = htmlReadIO(fuzz_ioread, fuzz_ioclose, &ctx, NULL, NULL, 0);

    if (doc != NULL) {
        /* Free the parsed document to avoid memory leaks across runs. */
        xmlFreeDoc(doc);
    }

    /* Do not call xmlCleanupParser() here: it's global and can affect subsequent runs */
    return 0;
}
