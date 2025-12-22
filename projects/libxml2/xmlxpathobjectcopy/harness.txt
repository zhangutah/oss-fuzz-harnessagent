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
// // xmlXPathObject *
// //xmlXPathVariableLookupNS(xmlXPathContext *ctxt, const xmlChar *name,
// //			 const xmlChar *ns_uri) {
// //    if (ctxt == NULL)
// //	return(NULL);
// //
// //    if (ctxt->varLookupFunc != NULL) {
// //	xmlXPathObjectPtr ret;
// //
// //	ret = ((xmlXPathVariableLookupFunc)ctxt->varLookupFunc)
// //	        (ctxt->varLookupData, name, ns_uri);
// //	if (ret != NULL) return(ret);
// //    }
// //
// //    if (ctxt->varHash == NULL)
// //	return(NULL);
// //    if (name == NULL)
// //	return(NULL);
// //
// //    return(xmlXPathObjectCopy(xmlHashLookup2(ctxt->varHash, name, ns_uri)));
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlXPathObject * xmlXPathObjectCopy(xmlXPathObject * val);
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

/* Prefer absolute project headers as discovered. */
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/parser.h"

/*
 Fuzzer entry point to exercise xmlXPathObjectCopy.
 This harness builds a small xmlXPathObject from the input bytes,
 exercising different branches (boolean, number, string, nodeset, users, xslt tree).
 It then calls xmlXPathObjectCopy and frees both original and copied objects.
*/

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser (safe no-op if already done) */
    xmlInitParser();

    /* Choose a type based on first byte */
    uint8_t selector = Data[0];
    const xmlXPathObjectType candidates[] = {
        XPATH_UNDEFINED,
        XPATH_NODESET,
        XPATH_BOOLEAN,
        XPATH_NUMBER,
        XPATH_STRING,
        XPATH_USERS,
        XPATH_XSLT_TREE
    };
    const size_t cand_len = sizeof(candidates) / sizeof(candidates[0]);
    xmlXPathObjectType chosen_type = candidates[selector % cand_len];

    /* Prepare an xmlXPathObject on the heap to mimic a real object */
    xmlXPathObjectPtr val = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (val == NULL)
        return 0;
    /* zero-init to be safe */
    memset(val, 0, sizeof(xmlXPathObject));
    val->type = chosen_type;

    /* Use the remaining data to populate the fields depending on the type */
    const uint8_t *p = Data + 1;
    size_t remaining = (Size > 1) ? Size - 1 : 0;

    switch (chosen_type) {
        case XPATH_BOOLEAN: {
            if (remaining >= 1) {
                val->boolval = (p[0] & 1);
            } else {
                val->boolval = 0;
            }
            break;
        }
        case XPATH_NUMBER: {
            /* derive a double from up to 8 bytes */
            double d = 0.0;
            if (remaining >= sizeof(double)) {
                /* copy bytes into double */
                memcpy(&d, p, sizeof(double));
            } else if (remaining > 0) {
                /* small heuristic to build a double */
                uint64_t acc = 0;
                for (size_t i = 0; i < remaining; ++i) acc = (acc << 8) | p[i];
                d = (double)acc;
            }
            val->floatval = d;
            break;
        }
        case XPATH_STRING: {
            /* Create a null-terminated xmlChar* from remaining bytes (limit length) */
            size_t maxlen = remaining;
            if (maxlen > 1024) maxlen = 1024; /* avoid huge allocations */
            xmlChar *s = (xmlChar *) xmlMalloc(maxlen + 1);
            if (s != NULL) {
                if (maxlen > 0)
                    memcpy(s, p, maxlen);
                s[maxlen] = '\0';
                val->stringval = s;
            } else {
                val->stringval = NULL;
            }
            break;
        }
        case XPATH_NODESET:
        case XPATH_XSLT_TREE: {
            /* Build a small xmlNodeSet with up to N nodes derived from bytes */
            int max_nodes = 0;
            if (remaining >= 1) {
                max_nodes = p[0] % 5; /* small number of nodes 0..4 */
            }
            xmlNodeSetPtr ns = (xmlNodeSetPtr) xmlMalloc(sizeof(xmlNodeSet));
            if (ns == NULL) {
                val->nodesetval = NULL;
                break;
            }
            ns->nodeNr = 0;
            ns->nodeMax = max_nodes;
            ns->nodeTab = NULL;
            if (max_nodes > 0) {
                ns->nodeTab = (xmlNode **) xmlMalloc(sizeof(xmlNode *) * max_nodes);
                if (ns->nodeTab == NULL) {
                    xmlFree(ns);
                    val->nodesetval = NULL;
                    break;
                }
                /* Populate each xmlNode with minimal valid contents (zeroed) */
                size_t offset = 1;
                for (int i = 0; i < max_nodes; ++i) {
                    xmlNode *node = (xmlNode *) xmlMalloc(sizeof(xmlNode));
                    if (node == NULL) {
                        ns->nodeTab[i] = NULL;
                        continue;
                    }
                    /* zero-init; real xmlNode has many fields, but zero is safe for fuzzing */
                    memset(node, 0, sizeof(xmlNode));
                    /* optionally set the name field to point to small xmlChar from data */
                    if (offset < remaining) {
                        size_t namelen = remaining - offset;
                        if (namelen > 16) namelen = 16;
                        xmlChar *name = (xmlChar *) xmlMalloc(namelen + 1);
                        if (name) {
                            memcpy(name, p + offset, namelen);
                            name[namelen] = '\0';
                            node->name = name;
                        } else {
                            node->name = NULL;
                        }
                        offset += namelen;
                    } else {
                        node->name = NULL;
                    }
                    ns->nodeTab[i] = node;
                    ns->nodeNr++;
                }
            }
            val->nodesetval = ns;
            /* For XPATH_XSLT_TREE we leave additional semantics aside; boolval indicates not-owned */
            if (chosen_type == XPATH_XSLT_TREE)
                val->boolval = 1;
            break;
        }
        case XPATH_USERS: {
            /* set some opaque user pointer from data (not allocating real resources) */
            val->user = NULL;
            if (remaining >= sizeof(void *)) {
                /* fabricate a pointer value (will not be dereferenced) */
                void *tmp = NULL;
                memcpy(&tmp, p, sizeof(void *));
                val->user = tmp;
            }
            break;
        }
        case XPATH_UNDEFINED:
        default:
            /* leave other fields zeroed */
            break;
    }

    /* Now call the function under test */
    xmlXPathObject *copy = xmlXPathObjectCopy(val);

    /* If a copy was returned, free it via library free to exercise cleanup paths. */
    if (copy != NULL) {
        xmlXPathFreeObject(copy);
    }

    /* Free resources allocated for the original 'val' object.
       Note: xmlXPathFreeObject operates on xmlXPathObject* and will
       free nodesets/strings for that object. We must free the original val
       ourselves because it was allocated above. */
    if (val != NULL) {
        /* If we allocated a string, free it */
        if (val->type == XPATH_STRING && val->stringval != NULL) {
            xmlFree(val->stringval);
            val->stringval = NULL;
        }
        /* If we created a nodeset, free nodes and nodeTab and the set */
        if ((val->type == XPATH_NODESET || val->type == XPATH_XSLT_TREE) && val->nodesetval != NULL) {
            xmlNodeSetPtr ns = val->nodesetval;
            if (ns->nodeTab != NULL) {
                for (int i = 0; i < ns->nodeNr; ++i) {
                    if (ns->nodeTab[i] != NULL) {
                        /* If we allocated a name for the node, free it */
                        if (ns->nodeTab[i]->name != NULL) {
                            xmlFree((xmlChar *)ns->nodeTab[i]->name);
                            ns->nodeTab[i]->name = NULL;
                        }
                        xmlFree(ns->nodeTab[i]);
                    }
                }
                xmlFree(ns->nodeTab);
            }
            xmlFree(ns);
            val->nodesetval = NULL;
        }
        /* For user pointers we did not allocate memory that needs freeing here */
        xmlFree(val);
    }

    /* Cleanup parser (optional) */
    /* xmlCleanupParser();  -- do not call in libFuzzer typically to avoid reinit cost */
    return 0;
}
