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
// // void
// //xmlParseAttributeListDecl(xmlParserCtxt *ctxt) {
// //    const xmlChar *elemName;
// //    const xmlChar *attrName;
// //    xmlEnumerationPtr tree;
// //
// //    if ((CUR != '<') || (NXT(1) != '!'))
// //        return;
// //    SKIP(2);
// //
// //    if (CMP7(CUR_PTR, 'A', 'T', 'T', 'L', 'I', 'S', 'T')) {
// //#ifdef LIBXML_VALID_ENABLED
// //	int oldInputNr = ctxt->inputNr;
// //#endif
// //
// //	SKIP(7);
// //	if (SKIP_BLANKS_PE == 0) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //		                 "Space required after '<!ATTLIST'\n");
// //	}
// //        elemName = xmlParseName(ctxt);
// //	if (elemName == NULL) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_NAME_REQUIRED,
// //			   "ATTLIST: no name for Element\n");
// //	    return;
// //	}
// //	SKIP_BLANKS_PE;
// //	GROW;
// //	while ((RAW != '>') && (PARSER_STOPPED(ctxt) == 0)) {
// //	    int type;
// //	    int def;
// //	    xmlChar *defaultValue = NULL;
// //
// //	    GROW;
// //            tree = NULL;
// //	    attrName = xmlParseName(ctxt);
// //	    if (attrName == NULL) {
// //		xmlFatalErrMsg(ctxt, XML_ERR_NAME_REQUIRED,
// //			       "ATTLIST: no name for Attribute\n");
// //		break;
// //	    }
// //	    GROW;
// //	    if (SKIP_BLANKS_PE == 0) {
// //		xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //		        "Space required after the attribute name\n");
// //		break;
// //	    }
// //
// //	    type = xmlParseAttributeType(ctxt, &tree);
// //	    if (type <= 0) {
// //	        break;
// //	    }
// //
// //	    GROW;
// //	    if (SKIP_BLANKS_PE == 0) {
// //		xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //			       "Space required after the attribute type\n");
// //	        if (tree != NULL)
// //		    xmlFreeEnumeration(tree);
// //		break;
// //	    }
// //
// //	    def = xmlParseDefaultDecl(ctxt, &defaultValue);
// //	    if (def <= 0) {
// //                if (defaultValue != NULL)
// //		    xmlFree(defaultValue);
// //	        if (tree != NULL)
// //		    xmlFreeEnumeration(tree);
// //	        break;
// //	    }
// //	    if ((type != XML_ATTRIBUTE_CDATA) && (defaultValue != NULL))
// //	        xmlAttrNormalizeSpace(defaultValue, defaultValue);
// //
// //	    GROW;
// //            if (RAW != '>') {
// //		if (SKIP_BLANKS_PE == 0) {
// //		    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //			"Space required after the attribute default value\n");
// //		    if (defaultValue != NULL)
// //			xmlFree(defaultValue);
// //		    if (tree != NULL)
// //			xmlFreeEnumeration(tree);
// //		    break;
// //		}
// //	    }
// //	    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
// //		(ctxt->sax->attributeDecl != NULL))
// //		ctxt->sax->attributeDecl(ctxt->userData, elemName, attrName,
// //	                        type, def, defaultValue, tree);
// //	    else if (tree != NULL)
// //		xmlFreeEnumeration(tree);
// //
// //	    if ((ctxt->sax2) && (defaultValue != NULL) &&
// //	        (def != XML_ATTRIBUTE_IMPLIED) &&
// //		(def != XML_ATTRIBUTE_REQUIRED)) {
// //		xmlAddDefAttrs(ctxt, elemName, attrName, defaultValue);
// //	    }
// //	    if (ctxt->sax2) {
// //		xmlAddSpecialAttr(ctxt, elemName, attrName, type);
// //	    }
// //	    if (defaultValue != NULL)
// //	        xmlFree(defaultValue);
// //	    GROW;
// //	}
// //	if (RAW == '>') {
// //#ifdef LIBXML_VALID_ENABLED
// //	    if ((ctxt->validate) && (ctxt->inputNr > oldInputNr)) {
// //		xmlValidityError(ctxt, XML_ERR_ENTITY_BOUNDARY,
// //                                 "Attribute list declaration doesn't start and"
// //                                 " stop in the same entity\n",
// //                                 NULL, NULL);
// //	    }
// //#endif
// //	    NEXT;
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
//     int xmlParseAttributeType(xmlParserCtxt * ctxt, xmlEnumeration ** tree);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

/*
 * libxml2 headers - adjust include paths if needed for your build environment.
 * We include parserInternals.h to get the xmlParseAttributeType declaration
 * and the internal types used by the parser context.
 */
#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlIO.h>
#include <libxml/valid.h>
#include <libxml/tree.h>

/*
 * Fuzzer entry-point
 *
 * This fuzz driver wraps the libxml2 function:
 *   int xmlParseAttributeType(xmlParserCtxt *ctxt, xmlEnumeration **tree);
 *
 * Strategy:
 * - Create a new parser context (xmlNewParserCtxt).
 * - Create a parser input buffer from the fuzzer bytes (xmlParserInputBufferCreateMem).
 * - Create a new input stream (xmlNewInputStream), attach the buffer and reset it
 *   so the parser input pointers are initialized (xmlBufResetInput).
 * - Push the input onto the context stack (xmlCtxtPushInput).
 * - Call xmlParseAttributeType(ctxt, &tree).
 * - Clean up: free any enumeration returned and free the parser context.
 *
 * Note: xmlNewParserCtxt / xmlFreeParserCtxt handle freeing input streams pushed
 * onto the context, so we rely on xmlFreeParserCtxt for cleanup of inputs.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL) return 0;

    /* Initialize libxml (no-op if already initialized) */
    xmlInitParser();

    /* Create a parser context */
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Cap Size to INT_MAX for xmlParserInputBufferCreateMem which takes int */
    int bufSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /*
     * Create an input buffer from the fuzzer data. xmlParserInputBufferCreateMem
     * expects a (const char *) pointer and an int size. Passing XML_CHAR_ENCODING_NONE.
     */
    xmlParserInputBufferPtr inBuf = xmlParserInputBufferCreateMem((const char *)Data, bufSize, XML_CHAR_ENCODING_NONE);
    if (inBuf == NULL) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /*
     * Create a new input stream and attach the buffer.
     * xmlNewInputStream allocates xmlParserInput; we set its buf and reset it
     * so internal pointers (base/cur) are initialized from the buffer content.
     */
    xmlParserInputPtr input = xmlNewInputStream(ctxt);
    if (input == NULL) {
        xmlFreeParserInputBuffer(inBuf);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    input->buf = inBuf;
    /* Ensure the buffer content is associated with the input stream */
    if (inBuf->buffer != NULL)
        xmlBufResetInput(inBuf->buffer, input);

    /* Push the input into the context input stack */
    if (xmlCtxtPushInput(ctxt, input) < 0) {
        /* Push failed: free allocated resources */
        /* xmlFreeParserCtxt will not be called here because we need to free the buffer */
        /* but xmlCtxtPushInput failing means input was not integrated; free manually. */
        if (input != NULL) {
            /* detach buffer so xmlFreeInputStream won't attempt to free it twice */
            input->buf = NULL;
            xmlFreeInputStream(input);
        }
        if (inBuf != NULL)
            xmlFreeParserInputBuffer(inBuf);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Prepare variable to receive enumeration tree if produced */
    xmlEnumeration *tree = NULL;

    /* Call the target function under test. Wrap in a simple guard to avoid crashes propagating. */
    /* Many libxml2 APIs use the ctxt->input pointers, and we've set them via xmlBufResetInput + push. */
    (void)xmlParseAttributeType(ctxt, &tree);

    /* If an enumeration was returned, free it */
    if (tree != NULL) {
        xmlFreeEnumeration(tree);
        tree = NULL;
    }

    /* Free the parser context; this will free the pushed inputs as well */
    xmlFreeParserCtxt(ctxt);

    /* Optional cleanup of global parser state (safe to call repeatedly) */
    xmlCleanupParser();

    return 0;
}