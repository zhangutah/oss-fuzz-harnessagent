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
// // static void walkDoc(xmllintState *lint, xmlDocPtr doc) {
// //    FILE *errStream = lint->errStream;
// //    xmlTextReaderPtr reader;
// //    int ret;
// //
// //#ifdef LIBXML_PATTERN_ENABLED
// //    if (lint->pattern != NULL) {
// //        xmlNodePtr root;
// //        const xmlChar *namespaces[22];
// //        int i;
// //        xmlNsPtr ns;
// //
// //        root = xmlDocGetRootElement(doc);
// //        if (root == NULL ) {
// //            fprintf(errStream,
// //                    "Document does not have a root element");
// //            lint->progresult = XMLLINT_ERR_UNCLASS;
// //            return;
// //        }
// //        for (ns = root->nsDef, i = 0;ns != NULL && i < 20;ns=ns->next) {
// //            namespaces[i++] = ns->href;
// //            namespaces[i++] = ns->prefix;
// //        }
// //        namespaces[i++] = NULL;
// //        namespaces[i] = NULL;
// //
// //        ret = xmlPatternCompileSafe((const xmlChar *) lint->pattern, doc->dict,
// //                                    0, &namespaces[0], &lint->patternc);
// //	if (lint->patternc == NULL) {
// //            if (ret < 0) {
// //                lint->progresult = XMLLINT_ERR_MEM;
// //            } else {
// //                fprintf(errStream, "Pattern %s failed to compile\n",
// //                        lint->pattern);
// //                lint->progresult = XMLLINT_ERR_SCHEMAPAT;
// //            }
// //            goto error;
// //	}
// //
// //        lint->patstream = xmlPatternGetStreamCtxt(lint->patternc);
// //        if (lint->patstream == NULL) {
// //            lint->progresult = XMLLINT_ERR_MEM;
// //            goto error;
// //        }
// //
// //        ret = xmlStreamPush(lint->patstream, NULL, NULL);
// //        if (ret < 0) {
// //            fprintf(errStream, "xmlStreamPush() failure\n");
// //            lint->progresult = XMLLINT_ERR_MEM;
// //            goto error;
// //        }
// //    }
// //#endif /* LIBXML_PATTERN_ENABLED */
// //    reader = xmlReaderWalker(doc);
// //    if (reader != NULL) {
// //	if ((lint->appOptions & XML_LINT_TIMINGS) && (lint->repeat == 1)) {
// //	    startTimer(lint);
// //	}
// //	ret = xmlTextReaderRead(reader);
// //	while (ret == 1) {
// //	    if ((lint->appOptions & XML_LINT_DEBUG_ENABLED)
// //#ifdef LIBXML_PATTERN_ENABLED
// //	        || (lint->patternc)
// //#endif
// //	       )
// //		processNode(lint, reader);
// //	    ret = xmlTextReaderRead(reader);
// //	}
// //	if ((lint->appOptions & XML_LINT_TIMINGS) && (lint->repeat == 1)) {
// //	    endTimer(lint, "walking through the doc");
// //	}
// //	xmlFreeTextReader(reader);
// //	if (ret != 0) {
// //	    fprintf(errStream, "failed to walk through the doc\n");
// //	    lint->progresult = XMLLINT_ERR_UNCLASS;
// //	}
// //    } else {
// //	fprintf(errStream, "Failed to create a reader from the document\n");
// //	lint->progresult = XMLLINT_ERR_UNCLASS;
// //    }
// //
// //#ifdef LIBXML_PATTERN_ENABLED
// //error:
// //    if (lint->patternc != NULL) {
// //        xmlFreePattern(lint->patternc);
// //        lint->patternc = NULL;
// //    }
// //    if (lint->patstream != NULL) {
// //	xmlFreeStreamCtxt(lint->patstream);
// //	lint->patstream = NULL;
// //    }
// //#endif
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlTextReaderRead(xmlTextReader * reader);
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

/* Prefer project absolute headers (as requested). */
#include "/src/libxml2/include/libxml/xmlreader.h"
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"
#include "/src/libxml2/include/libxml/tree.h"

/*
 * Fuzzer entry point for xmlTextReaderRead
 *
 * This driver:
 *  - Creates an xmlTextReader from the provided input buffer via xmlReaderForMemory
 *  - Drives xmlTextReaderRead() until EOF/error
 *  - Calls a few accessor functions to exercise more code paths
 *  - Frees resources
 *
 * Note: Size may be larger than INT_MAX; xmlReaderForMemory takes an int for size,
 * so clamp to INT_MAX to avoid narrowing issues.
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) {
        return 0;
    }

    /* Clamp size to INT_MAX because xmlReaderForMemory expects an int size. */
    int len = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    /*
     * Initialize the libxml parser. It's safe to call multiple times; the
     * implementation guards reinitialization, though ideally done once.
     */
    xmlInitParser();

    /* Create a reader reading from the provided memory buffer */
    xmlTextReaderPtr reader = xmlReaderForMemory((const char *)Data, len, NULL, NULL, 0);
    if (reader == NULL) {
        /* Nothing to do; clean up and return */
        xmlCleanupParser();
        return 0;
    }

    /* Drive the reader: xmlTextReaderRead returns 1 for success (node), 0 for EOF, -1 for error */
    while (1) {
        int ret = xmlTextReaderRead(reader);
        if (ret <= 0) break; /* 0 = EOF, -1 = error */

        /* Call some small accessors to exercise additional logic */
        (void) xmlTextReaderNodeType(reader);
        (void) xmlTextReaderDepth(reader);

        const xmlChar *name = xmlTextReaderConstName(reader);
        /* name may be NULL for some node types; just touch it to avoid optimizing it out */
        if (name) {
            /* Access a byte to keep the pointer "used" (no allocation) */
            volatile unsigned char ch = name[0];
            (void)ch;
        }

        /* Try to read string content for nodes that have value; free if allocated */
        xmlChar *val = xmlTextReaderReadString(reader);
        if (val) {
            xmlFree(val);
        }

        /* Optionally move to attributes / other APIs could be exercised here,
           but keep this driver conservative to avoid modifying reader state in
           surprising ways for arbitrary fuzz input. */
    }

    /* Free the reader and cleanup parser state */
    xmlFreeTextReader(reader);
    xmlCleanupParser();

    return 0;
}