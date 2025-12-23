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
// // int main(int argc, char **argv) {
// //    xmlTextReaderPtr readerPtr;
// //    int i;
// //    xmlDocPtr docPtr;
// //
// //    if (argc < 2)
// //        return(1);
// //
// //    /*
// //     * this initialises the library and check potential ABI mismatches
// //     * between the version it was compiled for and the actual shared
// //     * library used.
// //     */
// //    LIBXML_TEST_VERSION
// //
// //    /*
// //     * Create a new reader for the first file and process the
// //     * document.
// //     */
// //    readerPtr = xmlReaderForFile(argv[1], NULL, 0);
// //    if (NULL == readerPtr) {
// //      fprintf(stderr, "%s: failed to create reader\n", argv[1]);      
// //      return(1);
// //    }
// //    processDoc(readerPtr);
// //
// //    /*
// //     * The reader can be reused for subsequent files.
// //     */
// //    for (i=2; i < argc; ++i) {
// //      	xmlReaderNewFile(readerPtr, argv[i], NULL, 0);
// //	if (NULL == readerPtr) {
// //	  fprintf(stderr, "%s: failed to create reader\n", argv[i]);      
// //	  return(1);
// //	}
// //        processDoc(readerPtr);
// //    }
// //
// //    /*
// //     * Since we've called xmlTextReaderCurrentDoc, we now have to
// //     * clean up after ourselves.  We only have to do this the last
// //     * time, because xmlReaderNewFile calls xmlCtxtReset which takes
// //     * care of it.
// //     */
// //    docPtr = xmlTextReaderCurrentDoc(readerPtr);
// //    if (docPtr != NULL)
// //      xmlFreeDoc(docPtr);
// //
// //    /*
// //     * Clean up the reader.
// //     */
// //    xmlFreeTextReader(readerPtr);
// //
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
//     int xmlReaderNewFile(xmlTextReader * reader, const char * filename, const char * encoding, int options);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Prefer absolute project headers per instructions */
#include "/src/libxml2/include/libxml/xmlreader.h"
#include "/src/libxml2/include/libxml/parser.h"

/*
 * Fuzzer entry point required by libFuzzer
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/*
 * Ensure libxml is initialized once.
 */
static int libxml_initialized = 0;
static void ensure_libxml_init(void) {
    if (!libxml_initialized) {
        /* LIBXML_TEST_VERSION checks ABI compatibility in many libxml examples */
        LIBXML_TEST_VERSION
        xmlInitParser();
        libxml_initialized = 1;
    }
}

/*
 * Simple helper: create a NUL-terminated copy of up to 'max_len' bytes
 * from Data[pos..]. Returns a malloc'd string (must be freed) or NULL.
 */
static char *copy_string_from_data(const uint8_t *Data, size_t Size, size_t pos, size_t max_len, size_t *out_consumed) {
    if (pos >= Size) {
        if (out_consumed) *out_consumed = 0;
        return NULL;
    }
    size_t avail = Size - pos;
    size_t len = avail < max_len ? avail : max_len;
    if (len == 0) {
        if (out_consumed) *out_consumed = 0;
        return NULL;
    }
    char *buf = (char *)malloc(len + 1);
    if (!buf) {
        if (out_consumed) *out_consumed = 0;
        return NULL;
    }
    memcpy(buf, Data + pos, len);
    buf[len] = '\0'; /* ensure NUL-termination */
    if (out_consumed) *out_consumed = len;
    return buf;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic validation */
    if (Data == NULL || Size == 0)
        return 0;

    ensure_libxml_init();

    size_t pos = 0;

    /* Extract an 'options' integer from the first up-to-4 bytes of input */
    int options = 0;
    if (Size - pos >= 4) {
        /* copy 4 bytes */
        uint32_t tmp;
        memcpy(&tmp, Data + pos, 4);
        options = (int)tmp;
        pos += 4;
    } else {
        /* less than 4 bytes -> build small options */
        for (; pos < Size && pos < 4; ++pos) {
            options = (options << 8) | Data[pos];
        }
    }

    /* Limit maximum lengths to avoid excessive allocations */
    const size_t MAX_FILENAME = 256;
    const size_t MAX_ENCODING = 64;

    /* Choose filename length as roughly half of remaining data, capped */
    size_t remaining = (pos < Size) ? (Size - pos) : 0;
    size_t fname_max_possible = remaining;
    size_t fname_len_wish = fname_max_possible / 2;
    if (fname_len_wish == 0 && remaining > 0) fname_len_wish = 1;
    if (fname_len_wish > MAX_FILENAME) fname_len_wish = MAX_FILENAME;
    if (fname_len_wish == 0) {
        /* No data left to form a filename; use an innocuous filename so xmlNewTextReaderFilename can succeed */
        fname_len_wish = 0;
    }

    /* Create filename string from Data (or leave it NULL to provoke xmlReaderNewFile error handling) */
    char *filename = NULL;
    size_t consumed_fname = 0;
    if (fname_len_wish > 0) {
        filename = copy_string_from_data(Data, Size, pos, fname_len_wish, &consumed_fname);
        pos += consumed_fname;
    }

    /* Create encoding string from remaining data (if any) */
    size_t consumed_enc = 0;
    char *encoding = NULL;
    if (pos < Size) {
        size_t enc_max = Size - pos;
        if (enc_max > MAX_ENCODING) enc_max = MAX_ENCODING;
        encoding = copy_string_from_data(Data, Size, pos, enc_max, &consumed_enc);
        pos += consumed_enc;
    }

    /*
     * Create a xmlTextReader to pass to xmlReaderNewFile.
     * We'll attempt to create one from a benign existing filename ("/dev/null" on Unix).
     * If xmlNewTextReaderFilename fails, we cannot proceed safely.
     */
    xmlTextReader *reader = NULL;

    /* Try to obtain a reader from a known empty source; fallback to NULL if not possible */
#if defined(_WIN32) || defined(_WIN64)
    /* On Windows, use "NUL" device */
    reader = xmlNewTextReaderFilename("NUL");
#else
    reader = xmlNewTextReaderFilename("/dev/null");
#endif

    if (reader == NULL) {
        /* If we couldn't create a reader, attempt to create one from memory with a minimal buffer.
         * This is a best-effort fallback; if that also fails, bail out.
         */
        const char *small_xml = "<?xml version='1.0'?><root/>";
        xmlParserInputBufferPtr inbuf = xmlParserInputBufferCreateMem(small_xml, (int)strlen(small_xml), XML_CHAR_ENCODING_NONE);
        if (inbuf != NULL) {
            reader = xmlNewTextReader(inbuf, "about:blank");
            if (reader == NULL) {
                xmlFreeParserInputBuffer(inbuf);
            } else {
                /* mark that reader owns the input buffer in libxml internals; xmlNewTextReader already sets this */
            }
        }
    }

    if (reader == NULL) {
        /* Can't get a valid xmlTextReader; free temp strings and return */
        free(filename);
        free(encoding);
        return 0;
    }

    /* If filename is NULL, pass a harmless default to avoid unintended file system access to unpredictable paths */
    const char *call_filename = filename != NULL ? filename : "about:blank";

    /* Call the target function with fuzzed parameters */
    /* Note: xmlReaderNewFile returns 0 on success, -1 on error. We ignore the return value for fuzzing. */
    (void)xmlReaderNewFile(reader, call_filename, encoding, options);

    /* Cleanup */
    xmlFreeTextReader(reader);
    free(filename);
    free(encoding);

    /* Do not call xmlCleanupParser() here: it is global and may interfere with subsequent fuzzing iterations.
     * The fuzzer process will terminate eventually and the OS will reclaim resources.
     */

    return 0;
}
