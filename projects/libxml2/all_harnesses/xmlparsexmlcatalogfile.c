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
// //xmlFetchXMLCatalogFile(xmlCatalogEntryPtr catal) {
// //    xmlCatalogEntryPtr doc;
// //
// //    if (catal == NULL)
// //	return(-1);
// //    if (catal->URL == NULL)
// //	return(-1);
// //
// //    /*
// //     * lock the whole catalog for modification
// //     */
// //    xmlRMutexLock(&xmlCatalogMutex);
// //    if (catal->children != NULL) {
// //	/* Okay someone else did it in the meantime */
// //	xmlRMutexUnlock(&xmlCatalogMutex);
// //	return(0);
// //    }
// //
// //    if (xmlCatalogXMLFiles != NULL) {
// //	doc = (xmlCatalogEntryPtr)
// //	    xmlHashLookup(xmlCatalogXMLFiles, catal->URL);
// //	if (doc != NULL) {
// //	    if (xmlDebugCatalogs)
// //		xmlCatalogPrintDebug(
// //		    "Found %s in file hash\n", catal->URL);
// //
// //	    if (catal->type == XML_CATA_CATALOG)
// //		catal->children = doc->children;
// //	    else
// //		catal->children = doc;
// //	    catal->dealloc = 0;
// //	    xmlRMutexUnlock(&xmlCatalogMutex);
// //	    return(0);
// //	}
// //	if (xmlDebugCatalogs)
// //	    xmlCatalogPrintDebug(
// //		"%s not found in file hash\n", catal->URL);
// //    }
// //
// //    /*
// //     * Fetch and parse. Note that xmlParseXMLCatalogFile does not
// //     * use the existing catalog, there is no recursion allowed at
// //     * that level.
// //     */
// //    doc = xmlParseXMLCatalogFile(catal->prefer, catal->URL);
// //    if (doc == NULL) {
// //	catal->type = XML_CATA_BROKEN_CATALOG;
// //	xmlRMutexUnlock(&xmlCatalogMutex);
// //	return(-1);
// //    }
// //
// //    if (catal->type == XML_CATA_CATALOG)
// //	catal->children = doc->children;
// //    else
// //	catal->children = doc;
// //
// //    doc->dealloc = 1;
// //
// //    if (xmlCatalogXMLFiles == NULL)
// //	xmlCatalogXMLFiles = xmlHashCreate(10);
// //    if (xmlCatalogXMLFiles != NULL) {
// //	if (xmlDebugCatalogs)
// //	    xmlCatalogPrintDebug(
// //		"%s added to file hash\n", catal->URL);
// //	xmlHashAddEntry(xmlCatalogXMLFiles, catal->URL, doc);
// //    }
// //    xmlRMutexUnlock(&xmlCatalogMutex);
// //    return(0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlCatalogEntryPtr xmlParseXMLCatalogFile(xmlCatalogPrefer prefer, const xmlChar * filename);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   static xmlCatalogEntryPtr xmlParseXMLCatalogFile(xmlCatalogPrefer prefer, const xmlChar * filename);
// This harness writes the fuzzer input to a temporary file and calls the parser.
// It includes the implementation file directly so the static symbol is available.
#define LIBXML_CATALOG_ENABLED 1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Include the catalog implementation to get access to the static function.
// Use the project-relative path shown by the repository layout.
#include "/src/libxml2/catalog.c"

// Fuzzer entry point required by libFuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Create a temporary file for the catalog content
    char template_path[] = "/tmp/fuzz_xml_catalog_XXXXXX";
    int fd = mkstemp(template_path);
    if (fd < 0)
        return 0;

    // Write the fuzzer data to the temporary file
    ssize_t written = 0;
    const uint8_t *buf = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, buf + written, remaining);
        if (w <= 0) break;
        written += w;
        remaining -= (size_t)w;
    }
    // Close file descriptor (the file remains on disk)
    close(fd);

    // Choose prefer value based on first byte to exercise both branches
    xmlCatalogPrefer prefer = (Data[0] & 1) ? XML_CATA_PREFER_PUBLIC : XML_CATA_PREFER_SYSTEM;

    // Call the (static, included) function. It expects const xmlChar* (xmlChar is unsigned char).
    xmlCatalogEntryPtr entries = xmlParseXMLCatalogFile(prefer, (const xmlChar *)template_path);

    // Free returned catalog entries if any using the internal helper
    if (entries != NULL) {
        // xmlFreeCatalogEntryList is a static helper in catalog.c and available here because
        // the .c implementation was included into this translation unit.
        xmlFreeCatalogEntryList(entries);
    }

    // Remove the temporary file
    unlink(template_path);

    // Do a parser cleanup to avoid leaking global parser state across iterations
    // (best-effort; functions exist in libxml to cleanup)
#ifdef LIBXML2_VERSION
    /* If linking to libxml2 runtime functions, uncomment:
    xmlCleanupParser();
    */
#endif

    return 0;
}
