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
//     int xmllintShellRNGValidate(xmllintShellCtxtPtr sctxt, char * schemas, xmlNodePtr node, xmlNodePtr node2);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmllintShellRNGValidate(xmllintShellCtxtPtr sctxt, char * schemas, xmlNodePtr node, xmlNodePtr node2);
//
// This harness:
// - splits the fuzzer input into two parts: schema content and XML document content
// - writes the schema part to a temporary file and passes its path as `schemas`
// - parses the XML part with libxml2 to create a xmlDocPtr for sctxt->doc
// - constructs a minimal xmllintShellCtxt and calls xmllintShellRNGValidate
//
// Note: This driver includes the target implementation file to access the (static)
//       function xmllintShellRNGValidate directly. Adjust include path if needed.

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libxml/parser.h>
#include <libxml/relaxng.h>

// Include the target source to get access to the static function and types.
// Adjust the path if the source is located elsewhere in your build environment.
#include "/src/libxml2/shell.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // initialize libxml
    xmlInitParser();

    // split input into two halves: schema (first half) and xml doc (second half)
    size_t mid = Size / 2;
    const uint8_t *schemaData = Data;
    size_t schemaSize = mid;
    const uint8_t *xmlData = Data + mid;
    size_t xmlSize = Size - mid;

    // create temporary file for the Relax-NG schema
    char schema_path[] = "/tmp/fuzz_schemaXXXXXX";
    int fd = mkstemp(schema_path);
    if (fd == -1) {
        // fallback: still attempt with an empty schema path (will likely fail gracefully)
        fd = -1;
    } else {
        // write schema data
        ssize_t to_write = (ssize_t)schemaSize;
        ssize_t written = 0;
        while (written < to_write) {
            ssize_t ret = write(fd, schemaData + written, (size_t)(to_write - written));
            if (ret <= 0) break;
            written += ret;
        }
        fsync(fd);
        close(fd);
    }

    // parse the XML document from the input (if empty, use a minimal document)
    xmlDocPtr doc = NULL;
    if (xmlSize > 0) {
        // Use XML_PARSE_NONET to avoid network fetches and XML_PARSE_RECOVER to be tolerant.
        doc = xmlReadMemory((const char *)xmlData, (int)xmlSize, "fuzz.xml", NULL,
                            XML_PARSE_NONET | XML_PARSE_RECOVER);
    }
    if (doc == NULL) {
        // fallback to a tiny valid document
        const char *tiny = "<root/>";
        doc = xmlReadMemory(tiny, (int)strlen(tiny), "fuzz.xml", NULL, XML_PARSE_NONET);
    }

    // allocate and initialize the shell context
    xmllintShellCtxtPtr sctxt = (xmllintShellCtxtPtr) xmlMalloc(sizeof(xmllintShellCtxt));
    if (sctxt == NULL) {
        if (doc) xmlFreeDoc(doc);
        if (fd != -1) unlink(schema_path);
        xmlCleanupParser();
        return 0;
    }
    memset(sctxt, 0, sizeof(xmllintShellCtxt));

    sctxt->doc = doc;
    // store the schema path as filename so messages reference something meaningful
    if (fd != -1) {
        sctxt->filename = (char *) xmlStrdup((xmlChar *) schema_path);
    } else {
        sctxt->filename = (char *) xmlStrdup((xmlChar *) "(no-schema-file)");
    }
    // set output to /dev/null to avoid clutter
    sctxt->output = fopen("/dev/null", "w");
    if (sctxt->output == NULL) {
        // fallback to stdout if /dev/null cannot be opened
        sctxt->output = stdout;
    }
    sctxt->node = (xmlNodePtr) sctxt->doc;
    sctxt->loaded = 0;
#ifdef LIBXML_XPATH_ENABLED
    // if XPath is available, create a context; otherwise leave NULL
    sctxt->pctxt = xmlXPathNewContext(sctxt->doc);
#endif

    // Call the function under test.
    // If LIBXML_RELAXNG_ENABLED is not defined at compile time, xmllintShellRNGValidate
    // won't be present; however, including shell.c above should make it available
    // in this translation unit.
#ifdef LIBXML_RELAXNG_ENABLED
    // Use the temporary schema file path (or a fallback string)
    char *schemas_arg = (fd != -1) ? schema_path : "(no-schema-file)";
    // xmllintShellRNGValidate ignores node/node2 for its primary validation path,
    // so pass NULL for those.
    xmllintShellRNGValidate(sctxt, schemas_arg, NULL, NULL);
#endif

    // cleanup
#ifdef LIBXML_XPATH_ENABLED
    if (sctxt->pctxt != NULL)
        xmlXPathFreeContext(sctxt->pctxt);
#endif
    if (sctxt->filename != NULL)
        xmlFree((xmlChar *) sctxt->filename);
    if (sctxt->output && (sctxt->output != stdout))
        fclose(sctxt->output);
    if (sctxt)
        xmlFree(sctxt);

    if (doc)
        xmlFreeDoc(doc);

    if (fd != -1) {
        // remove temporary schema file
        unlink(schema_path);
    }

    xmlCleanupParser();
    return 0;
}
