#define LIBXML_CATALOG_ENABLED
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

/* Include the implementation so that static/internal functions are visible.
 * Path is the absolute path observed in the workspace.
 */
#include "/src/libxml2/catalog.c"

/* Fuzzer entry point. */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Create a temporary file to hold the input data. */
    char tmpname[] = "/tmp/libxml2_catalog_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        return 0;
    }

    /* Write the fuzzer input to the file (may contain NUL bytes). */
    if (Size > 0) {
        ssize_t written = write(fd, Data, Size);
        (void)written; /* ignore short writes for fuzzing */
        fsync(fd);
    }
    close(fd);

    /* Initialize libxml parser state (safe to call multiple times). */
    xmlInitParser();

    /* Create a catalog and call the target function. */
    xmlCatalogPtr catal = xmlNewCatalog(0); /* 0 => non-SGML XML catalog */
    if (catal != NULL) {
        /* Call the target function with the temp file name.
         * xmlExpandCatalog typically creates a catalog entry that references
         * the filename but defers parsing; force parsing of the file as well
         * so the fuzzer data is actually exercised by the XML parser.
         */
        (void) xmlExpandCatalog(catal, tmpname);

        /* Force parsing of the catalog file to ensure the fuzzer input is used. */
        xmlDocPtr doc = xmlParseCatalogFile(tmpname);
        if (doc != NULL) {
            /* Parsing the document will exercise XML parsing code paths. */
            xmlFreeDoc(doc);
        }

        /* Free catalog resources. */
        xmlFreeCatalog(catal);
    }

    /* Cleanup parser state. */
    xmlCleanupParser();

    /* Remove temporary file. */
    unlink(tmpname);

    return 0;
}