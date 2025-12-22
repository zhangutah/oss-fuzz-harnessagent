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
// // static void
// //xmlParsePERefInternal(xmlParserCtxt *ctxt, int markupDecl) {
// //    const xmlChar *name;
// //    xmlEntityPtr entity = NULL;
// //    xmlParserInputPtr input;
// //
// //    if (RAW != '%')
// //        return;
// //    NEXT;
// //    name = xmlParseName(ctxt);
// //    if (name == NULL) {
// //	xmlFatalErrMsg(ctxt, XML_ERR_PEREF_NO_NAME, "PEReference: no name\n");
// //	return;
// //    }
// //    if (RAW != ';') {
// //	xmlFatalErr(ctxt, XML_ERR_PEREF_SEMICOL_MISSING, NULL);
// //        return;
// //    }
// //
// //    NEXT;
// //
// //    /* Must be set before xmlHandleUndeclaredEntity */
// //    ctxt->hasPErefs = 1;
// //
// //    /*
// //     * Request the entity from SAX
// //     */
// //    if ((ctxt->sax != NULL) &&
// //	(ctxt->sax->getParameterEntity != NULL))
// //	entity = ctxt->sax->getParameterEntity(ctxt->userData, name);
// //
// //    if (entity == NULL) {
// //        xmlHandleUndeclaredEntity(ctxt, name);
// //    } else {
// //	/*
// //	 * Internal checking in case the entity quest barfed
// //	 */
// //	if ((entity->etype != XML_INTERNAL_PARAMETER_ENTITY) &&
// //	    (entity->etype != XML_EXTERNAL_PARAMETER_ENTITY)) {
// //	    xmlWarningMsg(ctxt, XML_WAR_UNDECLARED_ENTITY,
// //		  "Internal: %%%s; is not a parameter entity\n",
// //			  name, NULL);
// //	} else {
// //	    if ((entity->etype == XML_EXTERNAL_PARAMETER_ENTITY) &&
// //                ((ctxt->options & XML_PARSE_NO_XXE) ||
// //		 (((ctxt->loadsubset & ~XML_SKIP_IDS) == 0) &&
// //		  (ctxt->replaceEntities == 0) &&
// //		  (ctxt->validate == 0))))
// //		return;
// //
// //            if (entity->flags & XML_ENT_EXPANDING) {
// //                xmlFatalErr(ctxt, XML_ERR_ENTITY_LOOP, NULL);
// //                return;
// //            }
// //
// //	    input = xmlNewEntityInputStream(ctxt, entity);
// //	    if (xmlCtxtPushInput(ctxt, input) < 0) {
// //                xmlFreeInputStream(input);
// //		return;
// //            }
// //
// //            entity->flags |= XML_ENT_EXPANDING;
// //
// //            if (markupDecl)
// //                input->flags |= XML_INPUT_MARKUP_DECL;
// //
// //            GROW;
// //
// //	    if (entity->etype == XML_EXTERNAL_PARAMETER_ENTITY) {
// //                xmlDetectEncoding(ctxt);
// //
// //                if ((CMP5(CUR_PTR, '<', '?', 'x', 'm', 'l')) &&
// //                    (IS_BLANK_CH(NXT(5)))) {
// //                    xmlParseTextDecl(ctxt);
// //                }
// //            }
// //	}
// //    }
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlParserInput * xmlNewEntityInputStream(xmlParserCtxt * ctxt, xmlEntity * entity);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
// xmlParserInput * xmlNewEntityInputStream(xmlParserCtxt * ctxt, xmlEntity * entity);
//
// Fuzzer entry point:
//   int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
//
// Notes:
// - This driver builds a minimal xmlParserCtxt and xmlEntity, fills either entity->content
//   or entity->URI with fuzz data and calls xmlNewEntityInputStream.
// - It frees allocated resources after the call. It calls xmlInitParser/xmlCleanupParser
//   to initialize/cleanup libxml2 global state.
//
// Include the internal header that declares xmlNewEntityInputStream (absolute path
// from the project). Also include commonly used libxml2 headers.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "/src/libxml2/include/libxml/parserInternals.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/entities.h"
#include "/src/libxml2/include/libxml/tree.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fuzzer entry point expected by libFuzzer
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Basic sanity checks
    if (Data == NULL || Size == 0) return 0;

    // Initialize libxml2 global state
    xmlInitParser();

    // Create a parser context
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    // Allocate and zero an xmlEntity structure
    xmlEntityPtr ent = (xmlEntityPtr)calloc(1, sizeof(xmlEntity));
    if (ent == NULL) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    // Use fuzz data to decide whether to populate content or URI.
    // This gives two code paths inside xmlNewEntityInputStream:
    // - ent->content != NULL -> xmlCtxtNewInputFromString path
    // - ent->URI != NULL     -> xmlLoadResource path
    if (Data[0] % 2 == 0) {
        // Populate entity->content with a NUL-terminated copy of Data
        unsigned char *buf = (unsigned char *)malloc(Size + 1);
        if (buf != NULL) {
            memcpy(buf, Data, Size);
            buf[Size] = '\0';
            ent->content = (xmlChar *)buf;
            ent->length = (int)Size;
            // leave URI NULL
        }
    } else {
        // Populate entity->URI with a NUL-terminated copy of Data (as a string)
        char *uri = (char *)malloc(Size + 1);
        if (uri != NULL) {
            memcpy(uri, Data, Size);
            uri[Size] = '\0';
            ent->URI = (const xmlChar *)uri;
            // leave content NULL
        }
    }

    // Choose entity type (affects internal branch selecting resource type)
    // If second byte present and odd, consider it an external parameter entity.
    if (Size > 1 && (Data[1] & 1)) {
        ent->etype = XML_EXTERNAL_PARAMETER_ENTITY;
    } else {
        // Use an internal/general entity type
        ent->etype = XML_INTERNAL_PARAMETER_ENTITY;
    }

    // Call the target function under test.
    xmlParserInputPtr input = xmlNewEntityInputStream(ctxt, ent);

    // If an input was returned, free it.
    if (input != NULL) {
        xmlFreeInputStream(input);
    }

    // Free any buffers we allocated (xmlNewEntityInputStream uses XML_INPUT_BUF_STATIC
    // when given ent->content, so it will not free our buffer).
    if (ent->content != NULL) {
        free((void *)ent->content);
    }
    if (ent->URI != NULL) {
        free((void *)ent->URI);
    }

    // Free entity and parser context
    free(ent);
    xmlFreeParserCtxt(ctxt);

    // Cleanup libxml2 global state
    xmlCleanupParser();

    return 0;
}

#ifdef __cplusplus
} // extern "C"
#endif