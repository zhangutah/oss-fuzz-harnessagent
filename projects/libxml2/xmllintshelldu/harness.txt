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
//     int xmllintShellDu(xmllintShellCtxtPtr ctxt, char * arg, xmlNodePtr tree, xmlNodePtr node2);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for xmllintShellDu
// Compiles the shell implementation into this TU by including the source file,
// then drives xmllintShellDu using an XML parsed from the fuzzer input.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the implementation so the static function xmllintShellDu and
// xmllintShellCtxt are available in this translation unit.
// Adjust the path if needed by your build environment.
#include "/src/libxml2/shell.c"

// Fuzzer entry point
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Copy input into a nul-terminated buffer for libxml2
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Parse the input as an XML document. Use xmlReadMemory which is robust.
    // The function returns an xmlDocPtr which may be NULL on parse errors.
    xmlDocPtr doc = xmlReadMemory(buf, (int)Size, "fuzz.xml", NULL, 0);

    // Prepare a shell context. The definition is in the included shell.c.
    xmllintShellCtxt sctxt;
    memset(&sctxt, 0, sizeof(sctxt));
    sctxt.filename = NULL;
    sctxt.doc = doc;
    sctxt.node = NULL;
    sctxt.loaded = (doc != NULL);
    // Prefer a harmless output stream
    sctxt.output = stdout;
    if (sctxt.output == NULL) {
        // Fallback to a temporary file if stdout is unavailable
        sctxt.output = tmpfile();
    }

    // Determine the tree node to pass: root children of the document if available
    xmlNodePtr tree = NULL;
    if (doc != NULL) {
        tree = ((xmlDocPtr)doc)->children;
    }

    // Call the target function. It handles NULL tree gracefully by returning -1.
    // We ignore the return value; the goal is to exercise code paths.
    xmllintShellDu(&sctxt, NULL, tree, NULL);

    // Cleanup
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }
    xmlCleanupParser();

    if (sctxt.output && sctxt.output != stdout) {
        fclose(sctxt.output);
    }

    free(buf);
    return 0;
}
