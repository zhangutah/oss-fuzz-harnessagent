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
//     xmlAttrPtr xmlC14NFixupBaseAttr(xmlC14NCtxPtr ctx, xmlAttrPtr xml_base_attr);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     xmlAttrPtr xmlC14NFixupBaseAttr(xmlC14NCtxPtr ctx, xmlAttrPtr xml_base_attr);
//
// Fuzzer entrypoint:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
//
// This harness attempts to exercise xmlC14NFixupBaseAttr by:
//  - parsing the input bytes as an XML document (if possible)
//  - creating a small element tree (root -> mid -> leaf)
//  - creating an xml:base attribute on the leaf whose value is derived from the input
//  - creating an xml:base attribute on an ancestor (mid) to trigger uri building
//  - setting up a minimal xmlC14NCtx with an "always invisible" callback so the
//    function walks ancestors and processes xml:base attributes.
//  - calling xmlC14NFixupBaseAttr and freeing the returned attribute if any.
//
// Note: xmlC14NFixupBaseAttr is static inside c14n.c. To compile this harness
// the c14n.c source is included directly so the static symbol is available
// in this translation unit. The build environment must supply libxml2 headers
// and libraries paths accordingly.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlversion.h>

// Ensure the C14N implementation in c14n.c is compiled in when we include it.
#ifndef LIBXML_C14N_ENABLED
#define LIBXML_C14N_ENABLED
#endif

// Include the implementation directly so the static function xmlC14NFixupBaseAttr
// is available to call from this harness. Adjust the path if needed.
#include "/src/libxml2/c14n.c"

// Helper: a simple "invisible" callback to force the algorithm to walk ancestors.
// Returning 0 means "not visible", causing the while loop in xmlC14NFixupBaseAttr
// to iterate and look for ancestor xml:base attributes.
static int
always_invisible(void *user_data, xmlNodePtr node, xmlNodePtr parent) {
    (void)user_data;
    (void)node;
    (void)parent;
    return 0;
}

// Safe helper to create an xmlChar* string from fuzz bytes.
// Limit size to avoid huge allocations.
static xmlChar *
make_xmlchar_from_bytes(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return NULL;
    size_t limit = Size;
    if (limit > 4096) limit = 4096;
    xmlChar *buf = (xmlChar *)xmlMalloc(limit + 1);
    if (buf == NULL) return NULL;
    memcpy(buf, Data, limit);
    buf[limit] = '\0';
    return buf;
}

// The fuzzer entrypoint
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    xmlDocPtr doc = NULL;
    xmlNodePtr root = NULL;
    xmlNodePtr mid = NULL;
    xmlNodePtr leaf = NULL;
    xmlAttrPtr xml_base_attr = NULL;
    xmlAttrPtr ret_attr = NULL;
    xmlChar *child_val = NULL;
    xmlChar *ancestor_val = NULL;
    int created_doc = 0;

    // Initialize libxml parser (idempotent)
    xmlInitParser();

    // Try to parse the input as XML. Use recover to accept malformed inputs,
    // and XML_PARSE_DTDATTR | XML_PARSE_NOENT as recommended by c14n module.
    if (Size > 0) {
        // Use some common parse flags: recover, noent, dtdattr
        int parseFlags = XML_PARSE_RECOVER | XML_PARSE_NOENT | XML_PARSE_DTDATTR;
        doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL, parseFlags);
    }

    // If parsing failed, create a minimal document to host our test nodes.
    if (doc == NULL) {
        created_doc = 1;
        doc = xmlNewDoc(BAD_CAST "1.0");
        if (doc == NULL) {
            xmlCleanupParser();
            return 0;
        }
        root = xmlNewNode(NULL, BAD_CAST "root");
        if (root == NULL) {
            xmlFreeDoc(doc);
            xmlCleanupParser();
            return 0;
        }
        xmlDocSetRootElement(doc, root);
    } else {
        // Get (or create) root element
        root = xmlDocGetRootElement(doc);
        if (root == NULL) {
            // create one if parsed doc had no root
            root = xmlNewNode(NULL, BAD_CAST "root");
            if (root == NULL) {
                xmlFreeDoc(doc);
                xmlCleanupParser();
                return 0;
            }
            xmlDocSetRootElement(doc, root);
        }
    }

    // Build a small element tree: root -> mid -> leaf
    // If parsed doc already has a deeper structure, we still add ours as children.
    mid = xmlNewChild(root, NULL, BAD_CAST "mid", NULL);
    if (mid == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    leaf = xmlNewChild(mid, NULL, BAD_CAST "leaf", NULL);
    if (leaf == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    // Prepare attribute values from fuzz data if possible.
    // Use first half for leaf attribute, second half for ancestor (mid) attribute.
    if (Data != NULL && Size > 0) {
        size_t half = Size / 2;
        if (half == 0) half = Size; // for very small sizes
        child_val = make_xmlchar_from_bytes(Data, half);
        if (half < Size)
            ancestor_val = make_xmlchar_from_bytes(Data + half, Size - half);
        else
            ancestor_val = make_xmlchar_from_bytes(Data, Size);
    }

    // Fallback default strings if allocation failed or no input
    if (child_val == NULL) child_val = xmlStrdup(BAD_CAST "child_base_value");
    if (ancestor_val == NULL) ancestor_val = xmlStrdup(BAD_CAST "../ancestor/");

    // Ensure the xml namespace exists on root (xml prefix).
    // XML_XML_NAMESPACE is provided by libxml2 and equals the xml: namespace URI.
    xmlNsPtr xmlns = xmlNewNs(root, XML_XML_NAMESPACE, BAD_CAST "xml");
    // Create xml:base attribute on the mid (ancestor) to be discovered by the function.
    // This is the attribute that xmlC14NFixupBaseAttr may see when walking up.
    xmlAttrPtr mid_base = xmlNewNsProp(mid, xmlns, BAD_CAST "base", ancestor_val);
    // Create xml:base attribute on the leaf which will be passed to xmlC14NFixupBaseAttr.
    xml_base_attr = xmlNewNsProp(leaf, xmlns, BAD_CAST "base", child_val);

    // Prepare a minimal xmlC14NCtx
    xmlC14NCtx ctx_loc;
    memset(&ctx_loc, 0, sizeof(ctx_loc));
    ctx_loc.doc = doc;
    ctx_loc.is_visible_callback = always_invisible;
    ctx_loc.user_data = NULL;
    ctx_loc.with_comments = 0;
    ctx_loc.buf = NULL;
    ctx_loc.pos = XMLC14N_BEFORE_DOCUMENT_ELEMENT;
    ctx_loc.parent_is_doc = 0;
    ctx_loc.ns_rendered = NULL;
    ctx_loc.mode = XML_C14N_1_1; // pick 1.1 to exercise the special xml:base handling
    ctx_loc.inclusive_ns_prefixes = NULL;
    ctx_loc.error = 0;

    // Call the target function under test.
    // Protect with try/catch? C doesn't have; rely on libxml2 robustness.
    ret_attr = xmlC14NFixupBaseAttr(&ctx_loc, xml_base_attr);

    // If a new attribute was created, free it. The function's own comment in
    // the implementation indicates the caller must delete the returned attr node.
    if (ret_attr != NULL) {
        // xmlFreeProp frees a single attribute allocated by xmlNewNsProp/xmlNewProp.
        xmlFreeProp(ret_attr);
        ret_attr = NULL;
    }

    // Clean up: the created attributes that are attached to the document will
    // be freed by xmlFreeDoc below. Free any strings we allocated that are not
    // owned by the xml nodes (in our code, child_val/ancestor_val were allocated
    // with xmlMalloc or xmlStrdup and then attached; xmlNewNsProp copies/uses
    // the string as nodes' children, so free our copies only if they weren't attached).
    // In our flow, xmlNewNsProp does not take ownership of the passed buffer in all
    // cases, but to be safe, if they still exist free them.
    if (child_val != NULL) xmlFree(child_val);
    if (ancestor_val != NULL) xmlFree(ancestor_val);

    // Free the document and cleanup libxml
    if (doc != NULL) xmlFreeDoc(doc);
    xmlCleanupParser();

    return 0;
}
