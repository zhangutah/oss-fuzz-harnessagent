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
//     void xmlRelaxNGCheckGroupAttrs(xmlRelaxNGParserCtxtPtr ctxt, xmlRelaxNGDefinePtr def);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   void xmlRelaxNGCheckGroupAttrs(xmlRelaxNGParserCtxtPtr ctxt, xmlRelaxNGDefinePtr def);
// This harness includes the implementation file to allow calling the static function
// and builds minimal xmlRelaxNGParserCtxt and xmlRelaxNGDefine structures from the
// fuzzer input bytes.
//
// NOTE: The path below points to the source file in the project. Adjust if needed.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlstring.h>

/* Include the implementation so we can call the static function directly.
   Use the project-absolute path determined from the repository. */
#include "/src/libxml2/relaxng.c"

/* Helper: create an xmlChar* string from input bytes (null-terminated). */
static xmlChar *
mk_xmlchar(const uint8_t *data, size_t len) {
    if (len == 0) return NULL;
    /* limit length to avoid huge allocations */
    if (len > 64) len = 64;
    char *tmp = (char *)malloc(len + 1);
    if (tmp == NULL) return NULL;
    memcpy(tmp, data, len);
    tmp[len] = '\0';
    xmlChar *res = xmlStrdup((const xmlChar *)tmp);
    free(tmp);
    return res;
}

/* Helper: allocate and initialize an xmlRelaxNGDefine node populated from bytes */
static xmlRelaxNGDefinePtr
make_define_from_byte(const uint8_t b, const uint8_t *nameData, size_t nameLen,
                      const uint8_t *nsData, size_t nsLen) {
    xmlRelaxNGDefinePtr node = (xmlRelaxNGDefinePtr)malloc(sizeof(xmlRelaxNGDefine));
    if (node == NULL) return NULL;
    memset(node, 0, sizeof(*node));

    /* Choose a type based on byte value. Map into a set of useful types. */
    switch (b % 8) {
        case 0: node->type = XML_RELAXNG_ELEMENT; break;
        case 1: node->type = XML_RELAXNG_ATTRIBUTE; break;
        case 2: node->type = XML_RELAXNG_TEXT; break;
        case 3: node->type = XML_RELAXNG_DATATYPE; break;
        case 4: node->type = XML_RELAXNG_LIST; break;
        case 5: node->type = XML_RELAXNG_VALUE; break;
        case 6: node->type = XML_RELAXNG_CHOICE; break;
        default: node->type = XML_RELAXNG_GROUP; break;
    }

    /* Set name and ns from provided data (may be NULL). */
    if (nameData != NULL && nameLen > 0)
        node->name = mk_xmlchar(nameData, nameLen);
    else
        node->name = NULL;

    if (nsData != NULL && nsLen > 0)
        node->ns = mk_xmlchar(nsData, nsLen);
    else
        node->ns = NULL;

    /* other fields kept as NULL/0 */
    node->next = NULL;
    node->content = NULL;
    node->attrs = NULL;
    node->parent = NULL;
    node->nameClass = NULL;
    node->value = NULL;
    node->data = NULL;
    node->nextHash = NULL;
    node->depth = 0;
    node->dflags = 0;
    node->contModel = NULL;
    node->node = NULL;

    return node;
}

/* Cleanup a define node (free name/ns and the struct). */
static void
free_define_node(xmlRelaxNGDefinePtr n) {
    if (n == NULL) return;
    if (n->name) xmlFree(n->name);
    if (n->ns) xmlFree(n->ns);
    if (n->value) xmlFree(n->value);
    /* Note: We do not free content/next/attrs pointers here; caller should free lists. */
    free(n);
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size < 3) return 0;

    /* Initialize libxml (safe to call multiple times) */
    xmlInitParser();

    /* Build a minimal parser context */
    xmlRelaxNGParserCtxtPtr ctxt = (xmlRelaxNGParserCtxtPtr)malloc(sizeof(struct _xmlRelaxNGParserCtxt));
    if (ctxt == NULL) return 0;
    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->nbErrors = 0;
    ctxt->error = NULL;
    ctxt->warning = NULL;
    ctxt->serror = NULL;
    ctxt->schema = NULL;
    ctxt->grammar = NULL;
    ctxt->parentgrammar = NULL;
    ctxt->flags = 0;

    /* Interpret the first bytes to decide the def type and children counts */
    uint8_t b0 = Data[0];
    uint8_t b1 = Data[1];
    uint8_t b2 = Data[2];

    int is_group = (b0 & 1); /* 0 => ELEMENT, 1 => GROUP */
    int n_attrs = (b1 % 4);  /* cap attributes to 0..3 */
    int n_content = (b2 % 4);/* cap content to 0..3 */

    /* Keep offsets into the input for generating names */
    size_t offset = 3;

    /* Create the root 'def' */
    xmlRelaxNGDefinePtr def = (xmlRelaxNGDefinePtr)malloc(sizeof(xmlRelaxNGDefine));
    if (def == NULL) {
        free(ctxt);
        return 0;
    }
    memset(def, 0, sizeof(*def));
    def->type = is_group ? XML_RELAXNG_GROUP : XML_RELAXNG_ELEMENT;
    def->dflags = 0;
    def->node = NULL;

    /* Build attrs linked list */
    xmlRelaxNGDefinePtr prev = NULL;
    for (int i = 0; i < n_attrs; i++) {
        /* choose a byte for type and some bytes for name/ns from data */
        uint8_t typeByte = (offset < Size) ? Data[offset++] : 0;
        size_t nameLen = 0, nsLen = 0;
        const uint8_t *nameData = NULL, *nsData = NULL;

        if (offset < Size) {
            nameLen = (Data[offset] % 8);
            offset++;
            if (offset + nameLen <= Size) {
                nameData = &Data[offset];
                offset += nameLen;
            } else {
                nameLen = 0; nameData = NULL;
            }
        }
        if (offset < Size) {
            nsLen = (Data[offset] % 8);
            offset++;
            if (offset + nsLen <= Size) {
                nsData = &Data[offset];
                offset += nsLen;
            } else {
                nsLen = 0; nsData = NULL;
            }
        }

        xmlRelaxNGDefinePtr node = make_define_from_byte(typeByte, nameData, nameLen, nsData, nsLen);
        if (node == NULL) break;
        if (prev == NULL) {
            def->attrs = node;
        } else {
            prev->next = node;
        }
        prev = node;
    }

    /* Build content linked list */
    prev = NULL;
    for (int i = 0; i < n_content; i++) {
        uint8_t typeByte = (offset < Size) ? Data[offset++] : 0;
        size_t nameLen = 0, nsLen = 0;
        const uint8_t *nameData = NULL, *nsData = NULL;

        if (offset < Size) {
            nameLen = (Data[offset] % 8);
            offset++;
            if (offset + nameLen <= Size) {
                nameData = &Data[offset];
                offset += nameLen;
            } else {
                nameLen = 0; nameData = NULL;
            }
        }
        if (offset < Size) {
            nsLen = (Data[offset] % 8);
            offset++;
            if (offset + nsLen <= Size) {
                nsData = &Data[offset];
                offset += nsLen;
            } else {
                nsLen = 0; nsData = NULL;
            }
        }

        xmlRelaxNGDefinePtr node = make_define_from_byte(typeByte, nameData, nameLen, nsData, nsLen);
        if (node == NULL) break;
        if (prev == NULL) {
            def->content = node;
        } else {
            prev->next = node;
        }
        prev = node;
    }

    /* Ensure the parser context has nbErrors == 0 to allow checks to run */
    ctxt->nbErrors = 0;

    /* Call the target static function included from relaxng.c */
    xmlRelaxNGCheckGroupAttrs(ctxt, def);

    /* Minimal cleanup:
       - free the define nodes we allocated (names were duplicated with xmlStrdup; free with xmlFree)
       - NOTE: xmlRelaxNGCheckGroupAttrs will have allocated and freed temporary arrays internally.
    */
    xmlRelaxNGDefinePtr cur = def->attrs;
    while (cur != NULL) {
        xmlRelaxNGDefinePtr next = cur->next;
        free_define_node(cur);
        cur = next;
    }
    cur = def->content;
    while (cur != NULL) {
        xmlRelaxNGDefinePtr next = cur->next;
        free_define_node(cur);
        cur = next;
    }
    if (def->name) xmlFree(def->name);
    if (def->ns) xmlFree(def->ns);
    free(def);

    /* free parser context */
    free(ctxt);

    /* It's OK to leave libxml initialized for the fuzzer; optionally call xmlCleanupParser()
       but repeated calls can be expensive; we skip it for speed. */

    return 0;
}
