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
//     int xmllintShellLoad(xmllintShellCtxtPtr ctxt, char * filename, xmlNodePtr node, xmlNodePtr node2);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmllintShellLoad(xmllintShellCtxtPtr ctxt, char * filename, xmlNodePtr node, xmlNodePtr node2);
// Fuzzer entrypoint: LLVMFuzzerTestOneInput

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Include libxml headers (shell.c depends on them).
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/HTMLtree.h>

// Include the implementation unit so we can call the static function directly.
// Adjust the path if necessary in your build environment.
#include "/src/libxml2/shell.c"

// Note: shell.c declares the type xmllintShellCtxt and the static function
// xmllintShellLoad. By including the .c here we compile them into the same
// translation unit and can call the static function directly.

// Helper: write data to a temporary file and return its pathname (caller must unlink/free)
static char *write_to_tmpfile(const uint8_t *Data, size_t Size) {
    char template[] = "/tmp/fuzz_xml_XXXXXX";
    int fd = mkstemp(template);
    if (fd < 0) return NULL;

    ssize_t written = 0;
    const uint8_t *ptr = Data;
    size_t left = Size;
    while (left > 0) {
        ssize_t w = write(fd, ptr, left);
        if (w <= 0) break;
        written += w;
        ptr += w;
        left -= w;
    }
    close(fd);

    // Duplicate the pathname to return (mkstemp modified template in-place)
    char *path = strdup(template);
    return path;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    // Initialize libxml
    xmlInitParser();

    // Write the input bytes to a temp file (xmllintShellLoad expects a filename)
    char *tmpname = write_to_tmpfile(Data, Size);
    if (tmpname == NULL) {
        xmlCleanupParser();
        return 0;
    }

    // Prepare a shell context as defined in shell.c
    xmllintShellCtxtPtr ctxt = (xmllintShellCtxtPtr) calloc(1, sizeof(xmllintShellCtxt));
    if (ctxt == NULL) {
        unlink(tmpname);
        free(tmpname);
        xmlCleanupParser();
        return 0;
    }

    // Initialize fields conservatively
    ctxt->filename = NULL;
    ctxt->doc = NULL;
    ctxt->node = NULL;
#ifdef LIBXML_XPATH_ENABLED
    ctxt->pctxt = NULL;
#endif
    ctxt->loaded = 0;
    ctxt->output = stdout;

    // Call the target function. node and node2 parameters are unused by the function,
    // so pass NULL for them.
    // xmllintShellLoad is defined static in shell.c but visible here because shell.c
    // was included above.
    (void) xmllintShellLoad(ctxt, tmpname, NULL, NULL);

    // Cleanup resources possibly allocated by xmllintShellLoad.
    if (ctxt->loaded && ctxt->doc != NULL) {
        xmlFreeDoc(ctxt->doc);
        ctxt->doc = NULL;
    }
#ifdef LIBXML_XPATH_ENABLED
    if (ctxt->pctxt != NULL) {
        xmlXPathFreeContext(ctxt->pctxt);
        ctxt->pctxt = NULL;
    }
#endif
    if (ctxt->filename != NULL) {
        // xmlCanonicPath used inside may have allocated with xmlMalloc/xmlStrdup,
        // so use xmlFree to free it if available; otherwise fallback to free.
        xmlFree(ctxt->filename);
        ctxt->filename = NULL;
    }

    free(ctxt);

    // Remove the temporary file and free pathname
    unlink(tmpname);
    free(tmpname);

    xmlCleanupParser();
    return 0;
}
