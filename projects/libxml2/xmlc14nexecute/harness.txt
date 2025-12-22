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
// // int
// //xmlC14NDocSaveTo(xmlDoc *doc, xmlNodeSet *nodes,
// //                 int mode, xmlChar ** inclusive_ns_prefixes,
// //                 int with_comments, xmlOutputBuffer *buf) {
// //    return(xmlC14NExecute(doc,
// //			xmlC14NIsNodeInNodeset,
// //			nodes,
// //			mode,
// //			inclusive_ns_prefixes,
// //			with_comments,
// //			buf));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlC14NExecute(xmlDoc * doc, xmlC14NIsVisibleCallback is_visible_callback, void * user_data, int mode, xmlChar ** inclusive_ns_prefixes, int with_comments, xmlOutputBuffer * buf);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzzer driver for xmlC14NExecute
// Generated driver - full C source
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Include project headers (paths discovered in the workspace) */
#include "/src/libxml2/include/libxml/c14n.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Simple memory output buffer used as xmlOutputBuffer IO context.
 * The write callback appends written bytes into a growing buffer.
 */
struct mem_out {
    unsigned char *data;
    size_t len;
    size_t cap;
};

static int mem_write(void *context, const char *buffer, int len) {
    if (context == NULL || buffer == NULL || len <= 0)
        return 0;
    struct mem_out *m = (struct mem_out *)context;
    size_t need = m->len + (size_t)len;
    if (need > m->cap) {
        size_t newcap = m->cap ? m->cap * 2 : 1024;
        while (newcap < need) newcap *= 2;
        unsigned char *tmp = (unsigned char *)realloc(m->data, newcap);
        if (tmp == NULL) return -1;
        m->data = tmp;
        m->cap = newcap;
    }
    memcpy(m->data + m->len, buffer, (size_t)len);
    m->len += (size_t)len;
    return len;
}

static int mem_close(void *context) {
    /* Nothing special to do here. The fuzzer will free the backing buffer. */
    (void)context;
    return 0;
}

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser - safe to call multiple times */
    xmlInitParser();

    /* Prepare the input XML document by parsing the provided bytes.
     * Use recover and nonet to make parser tolerant and avoid network access.
     */
    int parseOptions = XML_PARSE_RECOVER | XML_PARSE_NONET;
    /* xmlReadMemory expects int size; cap to INT_MAX for safety */
    int docSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;
    xmlDocPtr doc = xmlReadMemory((const char *)Data, docSize, "fuzz.xml", NULL, parseOptions);

    /* Prepare output buffer that collects the C14N output in memory */
    struct mem_out out = { NULL, 0, 0 };
    xmlOutputBufferPtr outbuf = xmlOutputBufferCreateIO(
        (xmlOutputWriteCallback)mem_write,
        (xmlOutputCloseCallback)mem_close,
        &out,
        /* encoder */ NULL
    );

    if (outbuf == NULL) {
        if (doc != NULL) xmlFreeDoc(doc);
        /* free any allocated mem buffer (should be NULL) */
        free(out.data);
        xmlCleanupParser();
        return 0;
    }

    /* Choose mode and with_comments deterministically from input bytes to increase coverage */
    int mode = XML_C14N_1_0;
    int with_comments = 0;
    /* Use first byte to pick mode */
    unsigned char b0 = Data[0];
    switch (b0 % 3) {
        case 0: mode = XML_C14N_1_0; break;
        case 1: mode = XML_C14N_EXCLUSIVE_1_0; break;
        default: mode = XML_C14N_1_1; break;
    }
    /* Use second byte (if present) to decide with_comments */
    if (Size > 1) {
        unsigned char b1 = Data[1];
        with_comments = (b1 & 1);
    }

    /* Call xmlC14NExecute. Pass NULL as is_visible_callback and inclusive_ns_prefixes
     * to exercise the basic canonicalization path.
     */
    if (doc != NULL) {
        /* The function checks buf->encoder == NULL (C14N requires UTF-8), ensured above */
        (void)xmlC14NExecute(doc,
                             /* is_visible_callback */ NULL,
                             /* user_data */ NULL,
                             mode,
                             /* inclusive_ns_prefixes */ NULL,
                             with_comments,
                             outbuf);

        xmlFreeDoc(doc);
    } else {
        /* Even if parsing failed, we can still try calling xmlC14NExecute? Typically doc==NULL is rejected.
         * The function will return early if doc==NULL, but we avoid calling it with doc==NULL.
         */
    }

    /* Close and free the output buffer and our memory buffer */
    xmlOutputBufferClose(outbuf);
    free(out.data);

    /* Cleanup parser global state (okay for fuzzing harnesses) */
    xmlCleanupParser();

    return 0;
}
