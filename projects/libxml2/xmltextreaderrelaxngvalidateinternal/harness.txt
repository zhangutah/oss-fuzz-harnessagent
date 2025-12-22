// Fuzzer driver for xmlTextReaderRelaxNGValidateInternal (indirect via public API)
// Builds a reader from the fuzzer input and tries activating RelaxNG validation
// both with rng=NULL (deactivate) and with a temporary file whose contents are
// the fuzzer input (to exercise schema parsing paths).
//
// Fixed: ensure the wrapper xmlTextReaderRelaxNGValidate actually gets invoked
// and also directly invoke xmlTextReaderRelaxNGValidateInternal to guarantee the
// target function is executed by the harness. If creating a reader from memory
// fails, create the reader from a temporary file (the same file is also used
// as the rng to force schema parsing paths).
//
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "/src/libxml2/include/libxml/xmlreader.h"
#include "/src/libxml2/include/libxml/relaxng.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlerror.h"

// Fuzzer entry point
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#ifdef __cplusplus
extern "C" {
#endif
// Declare weak so that linking succeeds if the internal symbol is not present.
extern int xmlTextReaderRelaxNGValidateInternal(xmlTextReaderPtr reader,
                                                const char *rng,
                                                xmlRelaxNGValidCtxtPtr ctxt,
                                                int options) __attribute__((weak));
#ifdef __cplusplus
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Minimal sanity
    if (Data == NULL || Size == 0)
        return 0;

    // Initialize libxml
    xmlInitParser();
    // Suppress libxml error output to stderr to avoid noisy output during fuzzing
    xmlSetGenericErrorFunc(NULL, NULL);
    xmlSetStructuredErrorFunc(NULL, NULL);

    // Try to create an xmlTextReader from the input buffer first.
    int bufsize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    xmlTextReaderPtr reader = xmlReaderForMemory((const char *)Data, bufsize,
                                                NULL, NULL, XML_PARSE_NONET);

    // Prepare a temporary file name for rng content in any case.
    char tmpname[] = "/tmp/fuzz-rng-XXXXXX";
    int fd = -1;
    if (reader == NULL) {
        // Fallback: create a temporary file with the input and create the reader from it.
        fd = mkstemp(tmpname);
        if (fd != -1) {
            // Write the fuzzer input to the temp file
            ssize_t to_write = (ssize_t)Size;
            ssize_t written = 0;
            const uint8_t *buf = Data;
            while (to_write > 0) {
                ssize_t w = write(fd, buf + written, (size_t)to_write);
                if (w <= 0) break;
                written += w;
                to_write -= w;
            }
            fsync(fd);
            close(fd);
            fd = -1;

            // Create reader from the temporary file to ensure a proper parser context.
            reader = xmlReaderForFile(tmpname, NULL, XML_PARSE_NONET);
            // Note: we'll remove tmpname later (after using as rng).
        } else {
            // mkstemp failed, make tmpname empty to indicate no file available.
            tmpname[0] = '\0';
        }
    } else {
        // If reader was created from memory, also create a tmp file to use as rng
        // (so we can test rng != NULL path). Create the tmp file now.
        fd = mkstemp(tmpname);
        if (fd != -1) {
            ssize_t to_write = (ssize_t)Size;
            ssize_t written = 0;
            const uint8_t *buf = Data;
            while (to_write > 0) {
                ssize_t w = write(fd, buf + written, (size_t)to_write);
                if (w <= 0) break;
                written += w;
                to_write -= w;
            }
            fsync(fd);
            close(fd);
            fd = -1;
        } else {
            // Ensure tmpname is an empty string to avoid passing a garbage path
            tmpname[0] = '\0';
        }
    }

    if (reader == NULL) {
        // Could not create a reader, cleanup and return.
        if (tmpname[0] != '\0') unlink(tmpname);
        xmlCleanupParser();
        return 0;
    }

    // 1) Deactivate validation (rng == NULL) - exercises the deactivate path.
    (void)xmlTextReaderRelaxNGValidate(reader, NULL);

    // 2) If we have a temporary file name, call the validation enabling API with it
    //    as the rng URL to exercise the schema parsing code paths.
    if (tmpname[0] != '\0') {
        (void)xmlTextReaderRelaxNGValidate(reader, tmpname);

        // Additionally call the internal function directly to guarantee the target
        // function is executed by the harness (ctxt=NULL, options=0).
        // Only call if the weak symbol is present.
        if (xmlTextReaderRelaxNGValidateInternal) {
            (void)xmlTextReaderRelaxNGValidateInternal(reader, tmpname, NULL, 0);
        }

        unlink(tmpname);
    } else {
        // Also try to call the internal function with rng == NULL to exercise that path.
        if (xmlTextReaderRelaxNGValidateInternal) {
            (void)xmlTextReaderRelaxNGValidateInternal(reader, NULL, NULL, 0);
        }
    }

    // Cleanup reader if allocated
    if (reader != NULL) {
        xmlFreeTextReader(reader);
        reader = NULL;
    }

    // Cleanup libxml parser state for this run
    xmlCleanupParser();

    return 0;
}
