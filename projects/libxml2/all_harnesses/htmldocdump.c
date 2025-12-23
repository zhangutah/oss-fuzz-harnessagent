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
// //xmllintShellCat(xmllintShellCtxtPtr ctxt, char *arg ATTRIBUTE_UNUSED,
// //            xmlNodePtr node, xmlNodePtr node2 ATTRIBUTE_UNUSED)
// //{
// //    if (!ctxt)
// //        return (0);
// //    if (node == NULL) {
// //	fprintf(ctxt->output, "NULL\n");
// //	return (0);
// //    }
// //    if (ctxt->doc->type == XML_HTML_DOCUMENT_NODE) {
// //#ifdef LIBXML_HTML_ENABLED
// //        if (node->type == XML_HTML_DOCUMENT_NODE)
// //            htmlDocDump(ctxt->output, (htmlDocPtr) node);
// //        else
// //            htmlNodeDumpFile(ctxt->output, ctxt->doc, node);
// //#else
// //        if (node->type == XML_DOCUMENT_NODE)
// //            xmlDocDump(ctxt->output, (xmlDocPtr) node);
// //        else
// //            xmlElemDump(ctxt->output, ctxt->doc, node);
// //#endif /* LIBXML_HTML_ENABLED */
// //    } else {
// //        if (node->type == XML_DOCUMENT_NODE)
// //            xmlDocDump(ctxt->output, (xmlDocPtr) node);
// //        else
// //            xmlElemDump(ctxt->output, ctxt->doc, node);
// //    }
// //    fprintf(ctxt->output, "\n");
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
//     int htmlDocDump(FILE * f, xmlDoc * cur);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/* libxml2 headers */
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>
#include <libxml/tree.h>

/*
 Fuzzer entry point for htmlDocDump(FILE *f, xmlDoc *cur);

 Strategy:
 - Parse the input bytes as an HTML document using htmlReadMemory.
 - If a document is returned, call htmlDocDump writing to a temporary FILE* (tmpfile()).
 - Clean up all libxml2 resources.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* htmlReadMemory expects an int for size; cap to INT_MAX to avoid overflow. */
    int in_size = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /* Parse the input bytes as HTML. Use NULL for URL and encoding, options=0. */
    xmlDocPtr doc = htmlReadMemory((const char *)Data, in_size, NULL, NULL, 0);
    if (doc == NULL) {
        /* Nothing parsed -> nothing to dump. */
        return 0;
    }

    /* Open a temporary file to receive htmlDocDump output. tmpfile() is standard. */
    FILE *out = tmpfile();
    if (out == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Call the target function under test. */
    /* htmlDocDump performs xmlInitParser internally, but calling it here is safe too. */
    (void)htmlDocDump(out, doc);

    /* Close the temporary file and free the parsed document. */
    fclose(out);
    xmlFreeDoc(doc);

    /* Optionally cleanup global parser state. This is harmless to call repeatedly. */
    xmlCleanupParser();

    return 0;
}