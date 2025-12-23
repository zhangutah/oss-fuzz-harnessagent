// Fuzz driver for:
//   int xmlC14NDocSave(xmlDoc * doc, xmlNodeSet * nodes, int mode,
//                      xmlChar ** inclusive_ns_prefixes, int with_comments,
//                      const char * filename, int compression);
//
// Fuzzer entry:
//   extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>

#include "/src/libxml2/include/libxml/c14n.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/xmlstring.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Basic checks
    if (Data == NULL || Size == 0) return 0;

    // Limit input size to avoid extremely large allocations from a single corpus item
    const size_t MAX_INPUT_SIZE = 1 << 20; // 1 MiB
    size_t to_use = Size;
    if (to_use > MAX_INPUT_SIZE) to_use = MAX_INPUT_SIZE;

    // Initialize parser (idempotent)
    xmlInitParser();

    // Create a temporary filename for xmlC14NDocSave to write to.
    // Use mkstemp so we get a real, writable path. mkstemp modifies the template.
    char template[] = "/tmp/fuzz-xmlc14n-XXXXXX";
    int fd = mkstemp(template);
    char *filename = NULL;
    if (fd >= 0) {
        close(fd); // xmlC14NDocSave will (re)open the file
        filename = template;
    } else {
        // fallback to a fixed name (less ideal)
        filename = "/tmp/fuzz-xmlc14n-fallback.out";
    }

    // Parse the input bytes to an XML document. Use xmlReadMemory to get an xmlDoc.
    // Use a non-zero name so parser errors reference something reasonable.
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)to_use, "fuzz_input.xml", NULL, 0);
    if (doc == NULL) {
        // Nothing to do if parsing failed.
        if (fd >= 0) unlink(filename);
        // Best-effort cleanup
        xmlCleanupParser();
        return 0;
    }

    // Choose mode, with_comments and compression from the input bytes (if available).
    // Safe defaults if Size is small.
    unsigned char b0 = Data[0];
    unsigned char b1 = (Size > 1) ? Data[1] : 0;
    unsigned char b2 = (Size > 2) ? Data[2] : 0;

    // xmlC14NMode is an int; typical values are small. Keep within small range.
    int mode = b0 & 0x7; // 0..7
    int with_comments = (b1 & 1) ? 1 : 0;

    // compression: negative means "use global default" in libxml; otherwise 0..9.
    // Map b2: if bit7 set -> -1, else 0..9
    int compression = (b2 & 0x80) ? -1 : (b2 % 10);

    // We do not supply a nodeset or inclusive namespace prefixes; pass NULL to
    // exercise the "whole document" path.
    xmlNodeSetPtr nodes = NULL;
    xmlChar **inclusive_ns_prefixes = NULL;

    // Call the target API. Surround with minimal protection: ensure filename not NULL.
    if (filename != NULL) {
        // xmlC14NDocSave returns number of bytes written >=0 on success, <0 on error.
        (void) xmlC14NDocSave(doc,
                              nodes,
                              mode,
                              inclusive_ns_prefixes,
                              with_comments,
                              filename,
                              compression);
    }

    // Cleanup: free the document and remove temp file.
    xmlFreeDoc(doc);
    if (fd >= 0) {
        // Remove the temporary file created by mkstemp
        unlink(filename);
    }

    // Note: xmlCleanupParser may free global state; it's acceptable to call here
    // in a fuzzing harness but is optional. Keep it to be tidy.
    xmlCleanupParser();
    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif