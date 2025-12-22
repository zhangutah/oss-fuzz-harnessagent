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
// //xmllintShellSetContent(xmllintShellCtxtPtr ctxt ATTRIBUTE_UNUSED,
// //            char *value, xmlNodePtr node,
// //            xmlNodePtr node2 ATTRIBUTE_UNUSED)
// //{
// //    xmlNodePtr results;
// //    xmlParserErrors ret;
// //
// //    if (!ctxt)
// //        return (0);
// //    if (node == NULL) {
// //	fprintf(ctxt->output, "NULL\n");
// //	return (0);
// //    }
// //    if (value == NULL) {
// //        fprintf(ctxt->output, "NULL\n");
// //	return (0);
// //    }
// //
// //    ret = xmlParseInNodeContext(node, value, strlen(value), 0, &results);
// //    if (ret == XML_ERR_OK) {
// //	if (node->children != NULL) {
// //	    xmlFreeNodeList(node->children);
// //	    node->children = NULL;
// //	    node->last = NULL;
// //	}
// //	xmlAddChildList(node, results);
// //    } else {
// //        fprintf(ctxt->output, "failed to parse content\n");
// //    }
// //    return (0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlNode * xmlAddChildList(xmlNode * parent, xmlNode * cur);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: xmlNode * xmlAddChildList(xmlNode * parent, xmlNode * cur);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver constructs xmlNode lists from the fuzzer input and calls
// xmlAddChildList(parent, cur). It exercises different shapes:
//  - cur == NULL
//  - one or many sibling nodes (built from input bytes)
// The nodes are created in a single xmlDoc so lifetime management is simple.
// The doc is freed after the call to let libxml2 clean up internal state.
//
// Build note (example):
//   cc -g -O1 -fsanitize=fuzzer,address -I/usr/include/libxml2 fuzz_xmlAddChildList.c -lxml2
//
// Include libxml2 public headers:
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Initialize libxml2 parser (safe to call multiple times).
    xmlInitParser();

    // Suppress libxml2 default error output to stderr to avoid noisy logs
    // during fuzzing runs; keep behavior simple.
    xmlSetGenericErrorFunc(NULL, NULL);

    // Create a new document and a parent node attached as the document root.
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL) {
        xmlCleanupParser();
        return 0;
    }

    xmlNodePtr parent = xmlNewNode(NULL, BAD_CAST "fuzz_parent");
    if (parent == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }
    // Set parent as the root element so it is associated with the doc.
    xmlDocSetRootElement(doc, parent);

    // Use the first byte as a small selector to vary scenarios.
    size_t pos = 0;
    unsigned char selector = Data[pos++];
    selector = selector % 4; // 0..3

    xmlNodePtr cur = NULL;        // head of the sibling list to pass as 'cur'
    xmlNodePtr last = NULL;       // tail pointer for linking siblings

    // Scenario selection:
    // 0 -> cur == NULL
    // 1 -> single node built from remaining input
    // 2 -> multiple nodes (up to 50) built from remaining input
    // 3 -> build nodes but set some small content variations
    if (selector == 0) {
        cur = NULL;
    } else {
        // Determine how many nodes we can build from remaining bytes.
        size_t remaining = (pos < Size) ? (Size - pos) : 0;
        if (remaining == 0) {
            // No bytes left: create a single empty node
            xmlNodePtr n = xmlNewDocNode(doc, NULL, BAD_CAST "node", NULL);
            if (n != NULL) {
                cur = n;
                last = n;
            }
        } else {
            // Limit to a reasonable number of nodes to avoid pathological allocations.
            const size_t MAX_NODES = 50;
            size_t nodes = remaining;
            if (nodes > MAX_NODES) nodes = MAX_NODES;

            // Build nodes using successive bytes; each node gets a small name and optional content.
            for (size_t i = 0; i < nodes && pos < Size; ++i, ++pos) {
                // Build a small stable name from the byte value, e.g. nXX
                char namebuf[8];
                snprintf(namebuf, sizeof(namebuf), "n%02x", Data[pos]);

                // Create the node in the same doc.
                xmlNodePtr n = xmlNewDocNode(doc, NULL, BAD_CAST namebuf, NULL);
                if (n == NULL) {
                    // If creation fails, stop building further nodes.
                    break;
                }

                // Optionally set short textual content depending on selector to increase coverage.
                if (selector == 3) {
                    char content[32];
                    // derive some ASCII content from subsequent bytes if available
                    if (pos + 1 < Size) {
                        unsigned char b = Data[pos + 1];
                        snprintf(content, sizeof(content), "c%02x", b);
                    } else {
                        snprintf(content, sizeof(content), "c%02x", Data[pos]);
                    }
                    xmlNodeSetContent(n, BAD_CAST content);
                } else if (selector == 2) {
                    // Slight variation: use a number as content to exercise different code paths.
                    char content[16];
                    snprintf(content, sizeof(content), "%u", (unsigned)Data[pos]);
                    xmlNodeSetContent(n, BAD_CAST content);
                }
                // Link into sibling list (cur is head)
                if (cur == NULL) {
                    cur = n;
                    last = n;
                } else {
                    last->next = n;
                    n->prev = last;
                    last = n;
                }
            }
        }
    }

    // Call the targeted function under test.
    // It is expected to attach the nodes from cur as children of parent.
    // We intentionally call it with a variety of shaped inputs constructed above.
    // Protect the call region minimally: many crashes will be surfaced to the fuzzer.
    (void)xmlAddChildList(parent, cur);

    // Free the document. This will free parent and all nodes created above
    // (whether they were attached to parent or not), avoiding memory leaks.
    xmlFreeDoc(doc);

    // Clean up parser state.
    xmlCleanupParser();

    return 0;
}
