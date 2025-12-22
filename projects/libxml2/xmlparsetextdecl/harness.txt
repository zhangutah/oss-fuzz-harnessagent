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
//     void xmlParseTextDecl(xmlParserCtxt * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <libxml/parserInternals.h>
#include <libxml/parser.h>

/* xmlCtxtNewInputFromMemory is not part of the public headers in some
 * libxml2 builds. Provide a local prototype so we can call it if available.
 * The real symbol is in the libxml2 build and will be linked at link time.
 */
extern xmlParserInputPtr
xmlCtxtNewInputFromMemory(xmlParserCtxt *ctxt,
                          const char *url,
                          const void *mem,
                          size_t size,
                          const char *encoding,
                          xmlParserInputFlags flags);

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml (idempotent) */
    xmlInitParser();

    /* Create a new parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL)
        return 0;

    /* Create a parser input from the fuzz data (memory). Passing flags=0. */
    xmlParserInputPtr input = NULL;
    /* Try to use the context-aware helper if available. If it returns NULL,
       try to fall back to the non-context helper if present. */
    input = xmlCtxtNewInputFromMemory(ctxt, /*url*/NULL, (const void *)Data, Size, /*encoding*/NULL, 0);

    if (input == NULL) {
        /* Clean up and return if we couldn't create an input */
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Push the input onto the parser context so ctxt->input points to it. */
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        xmlFreeParserCtxt(ctxt);
        return 0;
    }

    /* Call the function under test. It will operate on ctxt->input. */
    xmlParseTextDecl(ctxt);

    /* Clean up */
    xmlFreeParserCtxt(ctxt);

    return 0;
}