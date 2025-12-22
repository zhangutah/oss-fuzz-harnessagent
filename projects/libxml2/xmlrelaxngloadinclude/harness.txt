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
//     xmlRelaxNGIncludePtr xmlRelaxNGLoadInclude(xmlRelaxNGParserCtxtPtr ctxt, const xmlChar * URL, xmlNodePtr node, const xmlChar * ns);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzzer harness for:
//   xmlRelaxNGIncludePtr xmlRelaxNGLoadInclude(xmlRelaxNGParserCtxtPtr ctxt,
//                                              const xmlChar * URL,
//                                              xmlNodePtr node,
//                                              const xmlChar * ns);
//
// Notes:
// - The function is defined in relaxng.c as a static symbol. To be able to call it
//   from this single translation unit we include the C source directly. This is a
//   common technique for harnessing static/internal functions when building a
//   standalone fuzzer target.
// - The harness writes fuzzer input to a temporary file and passes its path as the
//   URL to xmlRelaxNGLoadInclude so the code path that loads and parses included
//   schemas may be exercised.
// - Cleanup is performed to avoid leaking files or libxml resources.
//
// Compile (example):
//   clang -g -O1 -fsanitize=address,fuzzer <this_file.c> -I/src/libxml2/include -o fuzz_relaxng
//
// (Adjust include paths / compile flags according to your environment.)

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlreader.h>

// Include the relaxng implementation directly so we can call the static
// xmlRelaxNGLoadInclude function defined there. Path is the project-relative
// or absolute path discovered in the repository environment.
#include "/src/libxml2/relaxng.c"

// Fuzzer entry point expected by libFuzzer / LLVM's fuzzing infra.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize libxml (safe to call multiple times).
    xmlInitParser();

    // Create a temporary file and write the fuzzer data into it. The relaxng
    // include loader will treat the filename as a URL (file path) to load.
    char tmpl[] = "/tmp/libxml2_rng_XXXXXX.rng";
    int fd = mkstemps(tmpl, 4); // keep ".rng" suffix in the name
    if (fd == -1) {
        // Could not create temp file; nothing to do.
        xmlCleanupParser();
        return 0;
    }

    // Write the data to the file.
    ssize_t to_write = (ssize_t)Size;
    const uint8_t *p = Data;
    while (to_write > 0) {
        ssize_t written = write(fd, p, to_write);
        if (written <= 0) break;
        p += written;
        to_write -= written;
    }
    // Ensure file is flushed.
    fsync(fd);
    close(fd);

    // Create a RelaxNG parser context for the temporary file.
    // The parser context creation will record the URL and may parse parts
    // lazily when includes are processed.
    xmlRelaxNGParserCtxtPtr pctxt = xmlRelaxNGNewParserCtxt(tmpl);
    if (pctxt == NULL) {
        // Cleanup and remove temp file.
        unlink(tmpl);
        xmlCleanupParser();
        return 0;
    }

    // Optionally set up structured error handlers / disable network fetching, etc.
    // For the harness keep defaults.

    // Create a minimal xmlNode to simulate an <include> node; the function
    // uses this only for error reporting in many cases, so a simple node is OK.
    xmlNodePtr node = xmlNewNode(NULL, BAD_CAST "include");
    if (node == NULL) {
        xmlRelaxNGFreeParserCtxt(pctxt);
        unlink(tmpl);
        xmlCleanupParser();
        return 0;
    }

    // Call the (previously static, included) function under test.
    // Passing ns == NULL for simplicity.
    // Note: xmlRelaxNGLoadInclude returns an xmlRelaxNGIncludePtr; we don't need
    // to introspect it fully here, but if non-NULL it registers the loaded doc
    // in the parser context; ensure we free parser context afterwards to release.
    xmlRelaxNGIncludePtr incl = xmlRelaxNGLoadInclude(pctxt, (const xmlChar *)tmpl, node, NULL);

    // If the include returned a structure, the parser context owns it via its
    // includes list. Freeing the parser context will clean it up. However, to be
    // defensive, if the include returned a doc not attached to the pctxt we free it.
    if (incl != NULL) {
        // In normal code xmlRelaxNGLoadInclude already registers the include
        // into ctxt->includes; we avoid double-free and rely on xmlRelaxNGFreeParserCtxt.
        // If you wanted to handle special cases, inspect incl->doc etc.
        (void)incl;
    }

    // Cleanup resources.
    xmlFreeNode(node);
    xmlRelaxNGFreeParserCtxt(pctxt);

    // Remove temporary file.
    unlink(tmpl);

    // Optional libxml cleanup.
    xmlCleanupParser();

    return 0;
}
