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
//     void xmlSchemaSAXHandleEndElementNs(void * ctx, const xmlChar * localname, const xmlChar * prefix, const xmlChar * URI);
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

/*
 * Fuzz driver for:
 *   void xmlSchemaSAXHandleEndElementNs(void * ctx,
 *                                       const xmlChar * localname,
 *                                       const xmlChar * prefix,
 *                                       const xmlChar * URI);
 *
 * This harness tries to construct a minimal xmlSchemaValidCtxt and
 * xmlSchemaNodeInfo with safe fields so the function can be exercised.
 *
 * Note: This driver includes the library implementation source so the
 * static target function and related structs are available to the
 * harness at compile time. The absolute path below is based on the
 * project layout reported by the analysis tools.
 *
 * If you intend to build this outside of the checked-out project,
 * adjust the include path or build procedure accordingly.
 */

/* Include libxml2 headers (project-relative absolute paths discovered). */
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/xmlschemas.h"

/* Include the implementation so the static function and struct layouts are visible.
 * This may pull in many symbols; compile the harness in the same source tree.
 */
#include "/src/libxml2/xmlschemas.c"

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

/* Helper: duplicate a portion of the input into a null-terminated xmlChar buffer.
 * The returned pointer must be freed by the caller (free()).
 */
static xmlChar *
dup_data_to_xmlchar(const uint8_t *data, size_t len) {
    xmlChar *buf = (xmlChar *)malloc(len + 1);
    if (buf == NULL)
        return NULL;
    if (len > 0)
        memcpy(buf, data, len);
    buf[len] = '\0';
    return buf;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Split the input into three parts: localname, prefix, URI.
     * If Size is small, some parts may be empty.
     */
    size_t part1 = Size / 3;
    size_t part2 = (Size - part1) / 2;
    size_t part3 = Size - part1 - part2;

    const uint8_t *p = Data;
    xmlChar *localname = dup_data_to_xmlchar(p, part1);
    p += part1;
    xmlChar *prefix = dup_data_to_xmlchar(p, part2);
    p += part2;
    xmlChar *uri = dup_data_to_xmlchar(p, part3);

    if (localname == NULL || prefix == NULL || uri == NULL) {
        free(localname);
        free(prefix);
        free(uri);
        return 0;
    }

    /*
     * Construct a minimal xmlSchemaValidCtxt and xmlSchemaNodeInfo so that
     * xmlSchemaSAXHandleEndElementNs can dereference the fields it needs.
     *
     * The full internal validator logic is complex; this harness only sets
     * a few fields used directly by the function:
     *   vctxt->skipDepth, vctxt->depth, vctxt->inode (with localName, nsName)
     *
     * We allocate the structures with malloc and zero them first.
     */

    xmlSchemaValidCtxtPtr vctxt = (xmlSchemaValidCtxtPtr)malloc(sizeof(xmlSchemaValidCtxt));
    if (vctxt == NULL) {
        free(localname); free(prefix); free(uri);
        return 0;
    }
    memset(vctxt, 0, sizeof(xmlSchemaValidCtxt));

    xmlSchemaNodeInfoPtr inode = (xmlSchemaNodeInfoPtr)malloc(sizeof(xmlSchemaNodeInfo));
    if (inode == NULL) {
        free(vctxt);
        free(localname); free(prefix); free(uri);
        return 0;
    }
    memset(inode, 0, sizeof(xmlSchemaNodeInfo));

    /* Populate the node info so xmlStrEqual comparisons are safe. */
    inode->localName = localname; /* note: reusing buffer pointers */
    inode->nsName = uri;

    /* Attach to validation context */
    vctxt->inode = inode;

    /* Set skipDepth to -1 to indicate no skipping (per code logic). */
    vctxt->skipDepth = -1;
    vctxt->depth = 0;
    /* parserCtxt may be NULL; xmlStopParser will check for NULL before use. */
    vctxt->parserCtxt = NULL;
    vctxt->err = 0;

    /* Call the target function with our crafted context and strings.
     * prefix may be unused in this function but we still pass it.
     */
    xmlSchemaSAXHandleEndElementNs((void *)vctxt, localname, prefix, uri);

    /* Clean up. Note: the function may not take ownership of the strings. */
    free(inode);
    free(vctxt);
    free(localname);
    free(prefix);
    free(uri);

    return 0;
}