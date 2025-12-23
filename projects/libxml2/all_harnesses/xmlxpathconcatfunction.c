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
//     void xmlXPathConcatFunction(xmlXPathParserContext * ctxt, int nargs);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   void xmlXPathConcatFunction(xmlXPathParserContext * ctxt, int nargs);
//
// Build assumptions: libxml2 headers and library are available to the build system.
//
// This driver:
// - Initializes libxml2
// - Creates an xmlXPathContext and xmlXPathParserContext
// - Splits the fuzzer input into N argument strings and pushes them on the parser
//   context value stack as XPath string objects
// - Calls xmlXPathConcatFunction with the chosen nargs
// - Cleans up allocated libxml2 structures
//
// Fuzzer entrypoint: LLVMFuzzerTestOneInput
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 (safe to call repeatedly) */
    xmlInitParser();

    /* Create a (minimal) XPath context. No xmlDoc is provided (NULL). */
    xmlXPathContextPtr xpathctxt = xmlXPathNewContext(NULL);
    if (xpathctxt == NULL)
        return 0;

    /* Create a parser context for XPath helper functions.
       Provide an empty expression string as initial input. */
    xmlXPathParserContextPtr pctxt = xmlXPathNewParserContext((const xmlChar *)"", xpathctxt);
    if (pctxt == NULL) {
        xmlXPathFreeContext(xpathctxt);
        return 0;
    }

    /* Choose nargs from the first input byte.
       Limit the maximum number of args to keep work small. */
    const unsigned int MAX_ARGS = 12;
    unsigned int nargs = Data[0] % (MAX_ARGS + 1); /* 0..MAX_ARGS */

    /* Prepare payload region (the rest of input) for splitting into argument strings */
    const uint8_t *payload = Data + 1;
    size_t payload_size = (Size > 1) ? (Size - 1) : 0;

    /* If there are arguments to push, split payload evenly among them.
       If payload is smaller than nargs, some args will be empty strings. */
    for (unsigned int i = 0; i < nargs; i++) {
        size_t start = (payload_size * i) / (nargs == 0 ? 1 : nargs);
        size_t end = (payload_size * (i + 1)) / (nargs == 0 ? 1 : nargs);
        size_t len = (end > start) ? (end - start) : 0;

        /* Allocate a NUL-terminated C string for this argument */
        char *arg = (char *)malloc(len + 1);
        if (arg == NULL) {
            /* push nothing further; let cleanup happen */
            break;
        }
        if (len)
            memcpy(arg, payload + start, len);
        arg[len] = '\0';

        /* Create an XPath string object and push it on the parser value stack.
           xmlXPathNewCString copies the value into the new object, so it's safe
           to free 'arg' immediately afterwards. */
        xmlXPathObject *obj = xmlXPathNewCString(arg);
        free(arg);

        if (obj == NULL) {
            /* Allocation failed; stop pushing further args */
            break;
        }

        /* Push the created object on the parser context value stack */
        xmlXPathValuePush(pctxt, obj);
    }

    /* Call the target function under test */
    xmlXPathConcatFunction(pctxt, (int)nargs);

    /* Free the parser context and the XPath context.
       xmlXPathFreeParserContext should release any XPath objects remaining on the stack. */
    xmlXPathFreeParserContext(pctxt);
    xmlXPathFreeContext(xpathctxt);

    /* Note: It's OK not to call xmlCleanupParser() in the fuzzer loop; if desired,
       the harness / fuzzer build can call xmlCleanupParser() at process teardown. */

    return 0;
}
