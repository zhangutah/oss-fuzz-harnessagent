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
// //xmlParseEntityDecl(xmlParserCtxt *ctxt) {
// //    const xmlChar *name = NULL;
// //    xmlChar *value = NULL;
// //    xmlChar *URI = NULL, *literal = NULL;
// //    const xmlChar *ndata = NULL;
// //    int isParameter = 0;
// //    xmlChar *orig = NULL;
// //
// //    if ((CUR != '<') || (NXT(1) != '!'))
// //        return;
// //    SKIP(2);
// //
// //    /* GROW; done in the caller */
// //    if (CMP6(CUR_PTR, 'E', 'N', 'T', 'I', 'T', 'Y')) {
// //#ifdef LIBXML_VALID_ENABLED
// //	int oldInputNr = ctxt->inputNr;
// //#endif
// //
// //	SKIP(6);
// //	if (SKIP_BLANKS_PE == 0) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //			   "Space required after '<!ENTITY'\n");
// //	}
// //
// //	if (RAW == '%') {
// //	    NEXT;
// //	    if (SKIP_BLANKS_PE == 0) {
// //		xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //			       "Space required after '%%'\n");
// //	    }
// //	    isParameter = 1;
// //	}
// //
// //        name = xmlParseName(ctxt);
// //	if (name == NULL) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_NAME_REQUIRED,
// //	                   "xmlParseEntityDecl: no name\n");
// //            return;
// //	}
// //	if (xmlStrchr(name, ':') != NULL) {
// //	    xmlNsErr(ctxt, XML_NS_ERR_COLON,
// //		     "colons are forbidden from entities names '%s'\n",
// //		     name, NULL, NULL);
// //	}
// //	if (SKIP_BLANKS_PE == 0) {
// //	    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //			   "Space required after the entity name\n");
// //	}
// //
// //	/*
// //	 * handle the various case of definitions...
// //	 */
// //	if (isParameter) {
// //	    if ((RAW == '"') || (RAW == '\'')) {
// //	        value = xmlParseEntityValue(ctxt, &orig);
// //		if (value) {
// //		    if ((ctxt->sax != NULL) &&
// //			(!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
// //			ctxt->sax->entityDecl(ctxt->userData, name,
// //		                    XML_INTERNAL_PARAMETER_ENTITY,
// //				    NULL, NULL, value);
// //		}
// //	    } else {
// //	        URI = xmlParseExternalID(ctxt, &literal, 1);
// //		if ((URI == NULL) && (literal == NULL)) {
// //		    xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, NULL);
// //		}
// //		if (URI) {
// //                    if (xmlStrchr(URI, '#')) {
// //                        xmlFatalErr(ctxt, XML_ERR_URI_FRAGMENT, NULL);
// //                    } else {
// //                        if ((ctxt->sax != NULL) &&
// //                            (!ctxt->disableSAX) &&
// //                            (ctxt->sax->entityDecl != NULL))
// //                            ctxt->sax->entityDecl(ctxt->userData, name,
// //                                        XML_EXTERNAL_PARAMETER_ENTITY,
// //                                        literal, URI, NULL);
// //                    }
// //		}
// //	    }
// //	} else {
// //	    if ((RAW == '"') || (RAW == '\'')) {
// //	        value = xmlParseEntityValue(ctxt, &orig);
// //		if ((ctxt->sax != NULL) &&
// //		    (!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
// //		    ctxt->sax->entityDecl(ctxt->userData, name,
// //				XML_INTERNAL_GENERAL_ENTITY,
// //				NULL, NULL, value);
// //		/*
// //		 * For expat compatibility in SAX mode.
// //		 */
// //		if ((ctxt->myDoc == NULL) ||
// //		    (xmlStrEqual(ctxt->myDoc->version, SAX_COMPAT_MODE))) {
// //		    if (ctxt->myDoc == NULL) {
// //			ctxt->myDoc = xmlNewDoc(SAX_COMPAT_MODE);
// //			if (ctxt->myDoc == NULL) {
// //			    xmlErrMemory(ctxt);
// //			    goto done;
// //			}
// //			ctxt->myDoc->properties = XML_DOC_INTERNAL;
// //		    }
// //		    if (ctxt->myDoc->intSubset == NULL) {
// //			ctxt->myDoc->intSubset = xmlNewDtd(ctxt->myDoc,
// //					    BAD_CAST "fake", NULL, NULL);
// //                        if (ctxt->myDoc->intSubset == NULL) {
// //                            xmlErrMemory(ctxt);
// //                            goto done;
// //                        }
// //                    }
// //
// //		    xmlSAX2EntityDecl(ctxt, name, XML_INTERNAL_GENERAL_ENTITY,
// //			              NULL, NULL, value);
// //		}
// //	    } else {
// //	        URI = xmlParseExternalID(ctxt, &literal, 1);
// //		if ((URI == NULL) && (literal == NULL)) {
// //		    xmlFatalErr(ctxt, XML_ERR_VALUE_REQUIRED, NULL);
// //		}
// //		if (URI) {
// //                    if (xmlStrchr(URI, '#')) {
// //                        xmlFatalErr(ctxt, XML_ERR_URI_FRAGMENT, NULL);
// //                    }
// //		}
// //		if ((RAW != '>') && (SKIP_BLANKS_PE == 0)) {
// //		    xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //				   "Space required before 'NDATA'\n");
// //		}
// //		if (CMP5(CUR_PTR, 'N', 'D', 'A', 'T', 'A')) {
// //		    SKIP(5);
// //		    if (SKIP_BLANKS_PE == 0) {
// //			xmlFatalErrMsg(ctxt, XML_ERR_SPACE_REQUIRED,
// //				       "Space required after 'NDATA'\n");
// //		    }
// //		    ndata = xmlParseName(ctxt);
// //		    if ((ctxt->sax != NULL) && (!ctxt->disableSAX) &&
// //		        (ctxt->sax->unparsedEntityDecl != NULL))
// //			ctxt->sax->unparsedEntityDecl(ctxt->userData, name,
// //				    literal, URI, ndata);
// //		} else {
// //		    if ((ctxt->sax != NULL) &&
// //		        (!ctxt->disableSAX) && (ctxt->sax->entityDecl != NULL))
// //			ctxt->sax->entityDecl(ctxt->userData, name,
// //				    XML_EXTERNAL_GENERAL_PARSED_ENTITY,
// //				    literal, URI, NULL);
// //		    /*
// //		     * For expat compatibility in SAX mode.
// //		     * assuming the entity replacement was asked for
// //		     */
// //		    if ((ctxt->replaceEntities != 0) &&
// //			((ctxt->myDoc == NULL) ||
// //			(xmlStrEqual(ctxt->myDoc->version, SAX_COMPAT_MODE)))) {
// //			if (ctxt->myDoc == NULL) {
// //			    ctxt->myDoc = xmlNewDoc(SAX_COMPAT_MODE);
// //			    if (ctxt->myDoc == NULL) {
// //			        xmlErrMemory(ctxt);
// //				goto done;
// //			    }
// //			    ctxt->myDoc->properties = XML_DOC_INTERNAL;
// //			}
// //
// //			if (ctxt->myDoc->intSubset == NULL) {
// //			    ctxt->myDoc->intSubset = xmlNewDtd(ctxt->myDoc,
// //						BAD_CAST "fake", NULL, NULL);
// //                            if (ctxt->myDoc->intSubset == NULL) {
// //                                xmlErrMemory(ctxt);
// //                                goto done;
// //                            }
// //                        }
// //			xmlSAX2EntityDecl(ctxt, name,
// //				          XML_EXTERNAL_GENERAL_PARSED_ENTITY,
// //				          literal, URI, NULL);
// //		    }
// //		}
// //	    }
// //	}
// //	SKIP_BLANKS_PE;
// //	if (RAW != '>') {
// //	    xmlFatalErrMsgStr(ctxt, XML_ERR_ENTITY_NOT_FINISHED,
// //	            "xmlParseEntityDecl: entity %s not terminated\n", name);
// //	} else {
// //#ifdef LIBXML_VALID_ENABLED
// //	    if ((ctxt->validate) && (ctxt->inputNr > oldInputNr)) {
// //		xmlValidityError(ctxt, XML_ERR_ENTITY_BOUNDARY,
// //	                         "Entity declaration doesn't start and stop in"
// //                                 " the same entity\n",
// //                                 NULL, NULL);
// //	    }
// //#endif
// //	    NEXT;
// //	}
// //	if (orig != NULL) {
// //	    /*
// //	     * Ugly mechanism to save the raw entity value.
// //	     */
// //	    xmlEntityPtr cur = NULL;
// //
// //	    if (isParameter) {
// //	        if ((ctxt->sax != NULL) &&
// //		    (ctxt->sax->getParameterEntity != NULL))
// //		    cur = ctxt->sax->getParameterEntity(ctxt->userData, name);
// //	    } else {
// //	        if ((ctxt->sax != NULL) &&
// //		    (ctxt->sax->getEntity != NULL))
// //		    cur = ctxt->sax->getEntity(ctxt->userData, name);
// //		if ((cur == NULL) && (ctxt->userData==ctxt)) {
// //		    cur = xmlSAX2GetEntity(ctxt, name);
// //		}
// //	    }
// //            if ((cur != NULL) && (cur->orig == NULL)) {
// //		cur->orig = orig;
// //                orig = NULL;
// //	    }
// //	}
// //
// //done:
// //	if (value != NULL) xmlFree(value);
// //	if (URI != NULL) xmlFree(URI);
// //	if (literal != NULL) xmlFree(literal);
// //        if (orig != NULL) xmlFree(orig);
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
//     xmlChar * xmlParseEntityValue(xmlParserCtxt * ctxt, xmlChar ** orig);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for xmlParseEntityValue
// Builds a parser context from the fuzzer input and calls
//    xmlChar * xmlParseEntityValue(xmlParserCtxt *ctxt, xmlChar ** orig);
// The entrypoint for libFuzzer is LLVMFuzzerTestOneInput.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/parserInternals.h>
#include <libxml/xmlstring.h>

// Ensure the libxml parser global initialization runs once.
static void ensure_libxml_initialized(void) {
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        initialized = 1;
    }
}

// Fuzzer entry point.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    ensure_libxml_initialized();

    // Make a nul-terminated copy of input data. The parser APIs may read
    // as a C string in some paths, so ensure safety.
    char *buf = (char *)malloc(Size + 1);
    if (buf == NULL)
        return 0;
    memcpy(buf, Data, Size);
    buf[Size] = '\0';

    // Create a memory parser context from the buffer.
    // xmlCreateMemoryParserCtxt expects (const char *buffer, int size).
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt(buf, (int)Size);
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    // Optionally, disable network/resource loading to limit side effects.
    // Many builds of libxml2 do this by default, but ensure common flags:
    ctxt->options |= XML_PARSE_NOENT | XML_PARSE_NONET;

    // Call the target function. Provide a pointer for orig to capture
    // the original entity value if produced.
    xmlChar *orig = NULL;
    xmlChar *res = NULL;

    // Call the deprecated/internal function under test.
    // It's expected to return a newly allocated xmlChar* or NULL.
    res = xmlParseEntityValue(ctxt, &orig);

    // Free results if provided.
    if (res != NULL) {
        xmlFree(res);
        res = NULL;
    }
    if (orig != NULL) {
        xmlFree(orig);
        orig = NULL;
    }

    // Clean up parser context and our input buffer.
    xmlFreeParserCtxt(ctxt);
    free(buf);

    // Do not call xmlCleanupParser() here: that can be heavy and is global.
    return 0;
}