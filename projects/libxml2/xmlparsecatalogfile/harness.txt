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
// // static xmlCatalogEntryPtr
// //xmlParseXMLCatalogFile(xmlCatalogPrefer prefer, const xmlChar *filename) {
// //    xmlDocPtr doc;
// //    xmlNodePtr cur;
// //    xmlChar *prop;
// //    xmlCatalogEntryPtr parent = NULL;
// //
// //    if (filename == NULL)
// //        return(NULL);
// //
// //    doc = xmlParseCatalogFile((const char *) filename);
// //    if (doc == NULL) {
// //	if (xmlDebugCatalogs)
// //	    xmlCatalogPrintDebug(
// //		    "Failed to parse catalog %s\n", filename);
// //	return(NULL);
// //    }
// //
// //    if (xmlDebugCatalogs)
// //	xmlCatalogPrintDebug(
// //		"Parsing catalog %s\n", filename);
// //
// //    cur = xmlDocGetRootElement(doc);
// //    if ((cur != NULL) && (xmlStrEqual(cur->name, BAD_CAST "catalog")) &&
// //	(cur->ns != NULL) && (cur->ns->href != NULL) &&
// //	(xmlStrEqual(cur->ns->href, XML_CATALOGS_NAMESPACE))) {
// //
// //	parent = xmlNewCatalogEntry(XML_CATA_CATALOG, NULL,
// //				    (const xmlChar *)filename, NULL, prefer, NULL);
// //        if (parent == NULL) {
// //	    xmlFreeDoc(doc);
// //	    return(NULL);
// //	}
// //
// //	prop = xmlGetProp(cur, BAD_CAST "prefer");
// //	if (prop != NULL) {
// //	    if (xmlStrEqual(prop, BAD_CAST "system")) {
// //		prefer = XML_CATA_PREFER_SYSTEM;
// //	    } else if (xmlStrEqual(prop, BAD_CAST "public")) {
// //		prefer = XML_CATA_PREFER_PUBLIC;
// //	    } else {
// //		xmlCatalogErr(NULL, cur, XML_CATALOG_PREFER_VALUE,
// //			      "Invalid value for prefer: '%s'\n",
// //			      prop, NULL, NULL);
// //	    }
// //	    xmlFree(prop);
// //	}
// //	cur = cur->children;
// //	xmlParseXMLCatalogNodeList(cur, prefer, parent, NULL);
// //    } else {
// //	xmlCatalogErr(NULL, (xmlNodePtr) doc, XML_CATALOG_NOT_CATALOG,
// //		      "File %s is not an XML Catalog\n",
// //		      filename, NULL, NULL);
// //	xmlFreeDoc(doc);
// //	return(NULL);
// //    }
// //    xmlFreeDoc(doc);
// //    return(parent);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDoc * xmlParseCatalogFile(const char * filename);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlDoc * xmlParseCatalogFile(const char * filename);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Build/link with libxml2 (e.g. -lxml2).
//
// This driver writes the input bytes to a temporary file and calls
// xmlParseCatalogFile() with that filename. Any returned xmlDoc is freed.
// xmlInitParser() is called once to initialize libxml2.

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <libxml/catalog.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

static void write_all(int fd, const uint8_t *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        p += w;
        len -= (size_t)w;
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    static int inited = 0;
    if (!inited) {
        /* Initialize libxml parser once per process. */
        xmlInitParser();
        inited = 1;
    }

    /* Create a uniquely-named temporary file for the catalog content. */
    char tmpl[] = "/tmp/fuzz_xml_catalog_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        /* If we can't create a temp file, give up this input. */
        return 0;
    }

    /* Write the fuzzer input into the file. It's okay if Size == 0. */
    if (Size > 0) {
        write_all(fd, Data, Size);
    }
    /* Ensure the data is flushed to disk for parsers that may mmap/read file. */
    fsync(fd);
    close(fd);

    /* Call the target function with the temp filename. */
    xmlDocPtr doc = xmlParseCatalogFile((const char *)tmpl);

    /* Free any returned document. xmlFreeDoc is safe with NULL. */
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    /* Remove the temporary file. */
    unlink(tmpl);

    /* Note: we do not call xmlCleanupParser() here since the process
       typically continues running and libFuzzer expects global state
       to remain valid across invocations. */
    return 0;
}

/* Optional standalone harness for local testing.
   Compile with: gcc -DTEST_MAIN fuzz_driver.c -lxml2 -o fuzz_driver
   Run: ./fuzz_driver sample_input_file
*/
#ifdef TEST_MAIN
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(f);
        return 1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        perror("ftell");
        fclose(f);
        return 1;
    }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        perror("fread");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    LLVMFuzzerTestOneInput(buf, (size_t)sz);

    free(buf);
    /* Clean up parser state before exit. */
    xmlCleanupParser();
    return 0;
}
#endif /* TEST_MAIN */