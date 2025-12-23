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
//     void xmlRelaxNGCheckChoiceDeterminism(xmlRelaxNGParserCtxtPtr ctxt, xmlRelaxNGDefinePtr def);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//     void xmlRelaxNGCheckChoiceDeterminism(xmlRelaxNGParserCtxtPtr ctxt, xmlRelaxNGDefinePtr def);
// Entry point:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 Include the library source containing the static target function so the
 static symbol is available in this translation unit. Use the absolute
 project path (adjust if the build environment places sources elsewhere).
*/
#include "/src/libxml2/relaxng.c"

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL)
        return 0;

    /* Create or obtain a parser context. Prefer the provided mem-parsing ctor. */
    xmlRelaxNGParserCtxtPtr ctxt = NULL;
    if (Size > 0) {
        /* xmlRelaxNGNewMemParserCtxt stores the pointer to buffer; that's fine for fuzzing. */
        ctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);
    }
    if (ctxt == NULL) {
        /* Fallback: allocate a minimal context to satisfy checks inside the function. */
        ctxt = (xmlRelaxNGParserCtxtPtr) xmlMalloc(sizeof(xmlRelaxNGParserCtxt));
        if (ctxt == NULL)
            return 0;
        memset(ctxt, 0, sizeof(xmlRelaxNGParserCtxt));
    }

    /* Ensure parser context won't early-exit due to parse errors count. */
    ctxt->nbErrors = 0;

    /* Build a xmlRelaxNGDefine structure populated from fuzz data. */
    xmlRelaxNGDefinePtr def = (xmlRelaxNGDefinePtr) xmlMalloc(sizeof(xmlRelaxNGDefine));
    if (def == NULL) {
        xmlRelaxNGFreeParserCtxt(ctxt);
        return 0;
    }
    memset(def, 0, sizeof(xmlRelaxNGDefine));

    /* Force the top-level type to CHOICE to exercise the target function early. */
    def->type = XML_RELAXNG_CHOICE;
    def->dflags = 0;

    /* Use fuzz data to build a small linked list of child definitions.
       Limit children to avoid excessive allocations. */
    size_t offset = 0;
    size_t max_children = 6;
    size_t nchildren = 0;
    if (Size > 0) {
        /* Use first byte to determine number of children (bounded). */
        nchildren = (size_t)(Data[0]) % (max_children + 1);
        offset = 1;
    }

    xmlRelaxNGDefinePtr prev = NULL;
    for (size_t i = 0; i < nchildren; i++) {
        xmlRelaxNGDefinePtr child = (xmlRelaxNGDefinePtr) xmlMalloc(sizeof(xmlRelaxNGDefine));
        if (child == NULL)
            break;
        memset(child, 0, sizeof(xmlRelaxNGDefine));

        /* Choose a type for the child from fuzz data if available. */
        int typeSel = 0;
        if (offset < Size) {
            typeSel = Data[offset++] % 4;
        }
        switch (typeSel) {
            case 0:
                child->type = XML_RELAXNG_TEXT;
                break;
            case 1:
                child->type = XML_RELAXNG_ELEMENT;
                break;
            case 2:
                child->type = XML_RELAXNG_LIST;
                break;
            default:
                child->type = XML_RELAXNG_ELEMENT;
                break;
        }

        /* If element, optionally set name and ns from fuzz data (short strings). */
        if (child->type == XML_RELAXNG_ELEMENT) {
            if (offset < Size) {
                int len = Data[offset++] % 16;
                if (len > 0 && offset + (size_t)len <= Size) {
                    /* xmlChar* allocations should be freed with xmlFree below. */
                    child->name = (xmlChar *) xmlStrndup((const xmlChar *)(Data + offset), len);
                    offset += (size_t)len;
                    /* small chance to set a namespace */
                    if (offset < Size && (Data[offset++] & 1)) {
                        int nslen = Data[offset++ % Size] % 8;
                        if (nslen > 0 && offset + (size_t)nslen <= Size) {
                            child->ns = (xmlChar *) xmlStrndup((const xmlChar *)(Data + offset), nslen);
                            offset += (size_t)nslen;
                        }
                    }
                }
            }
        }

        /* Link into the content list of the choice. */
        if (prev == NULL) {
            def->content = child;
        } else {
            prev->next = child;
        }
        prev = child;
    }

    /* Call the target function under fuzzing. This may set def->data (a hash table)
       or def->dflags; make sure we handle potential allocations on cleanup. */
    xmlRelaxNGCheckChoiceDeterminism(ctxt, def);

    /* Cleanup: free any hash table possibly attached to def->data. */
    if (def->data != NULL) {
        /* def->data is expected to be xmlHashTablePtr when set in the function. */
        xmlHashTablePtr tbl = (xmlHashTablePtr) def->data;
        if (tbl != NULL) {
            /* xmlHashFree is safe to call even if table internal buckets contain pointers we don't own. */
            xmlHashFree(tbl, NULL);
            def->data = NULL;
        }
    }

    /* Free allocated child nodes and their strings. */
    xmlRelaxNGDefinePtr cur = def->content;
    while (cur != NULL) {
        xmlRelaxNGDefinePtr next = cur->next;
        if (cur->name != NULL)
            xmlFree(cur->name);
        if (cur->ns != NULL)
            xmlFree(cur->ns);
        /* If these children had contModel or other pointers, we don't own them here. */
        xmlFree(cur);
        cur = next;
    }

    /* Free the top-level define and parser context. */
    xmlFree(def);

    /* Caller of xmlRelaxNGNewMemParserCtxt should use xmlRelaxNGFreeParserCtxt.
       If we used the fallback manual allocation, xmlRelaxNGFreeParserCtxt can still free safely
       as it expects a previously initialized structure. For safety call the provided free. */
    xmlRelaxNGFreeParserCtxt(ctxt);

    /* Some libxml2 global cleanup may be safe but is not required here; avoid calling
       xmlCleanupParser() inside the fuzzer loop. */

    return 0;
}