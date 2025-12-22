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
// // static xmlChar *
// //xmlParseAttValueInternal(xmlParserCtxtPtr ctxt, int *attlen, int *outFlags,
// //                         int special, int isNamespace) {
// //    unsigned maxLength = (ctxt->options & XML_PARSE_HUGE) ?
// //                         XML_MAX_HUGE_LENGTH :
// //                         XML_MAX_TEXT_LENGTH;
// //    xmlSBuf buf;
// //    xmlChar *ret;
// //    int c, l, quote, entFlags, chunkSize;
// //    int inSpace = 1;
// //    int replaceEntities;
// //    int normalize = (special & XML_SPECIAL_TYPE_MASK) > XML_ATTRIBUTE_CDATA;
// //    int attvalFlags = 0;
// //
// //    /* Always expand namespace URIs */
// //    replaceEntities = (ctxt->replaceEntities) || (isNamespace);
// //
// //    xmlSBufInit(&buf, maxLength);
// //
// //    GROW;
// //
// //    quote = CUR;
// //    if ((quote != '"') && (quote != '\'')) {
// //	xmlFatalErr(ctxt, XML_ERR_ATTRIBUTE_NOT_STARTED, NULL);
// //	return(NULL);
// //    }
// //    NEXTL(1);
// //
// //    if (ctxt->inSubset == 0)
// //        entFlags = XML_ENT_CHECKED | XML_ENT_VALIDATED;
// //    else
// //        entFlags = XML_ENT_VALIDATED;
// //
// //    inSpace = 1;
// //    chunkSize = 0;
// //
// //    while (1) {
// //        if (PARSER_STOPPED(ctxt))
// //            goto error;
// //
// //        if (CUR_PTR >= ctxt->input->end) {
// //            xmlFatalErrMsg(ctxt, XML_ERR_ATTRIBUTE_NOT_FINISHED,
// //                           "AttValue: ' expected\n");
// //            goto error;
// //        }
// //
// //        /*
// //         * TODO: Check growth threshold
// //         */
// //        if (ctxt->input->end - CUR_PTR < 10)
// //            GROW;
// //
// //        c = CUR;
// //
// //        if (c >= 0x80) {
// //            l = xmlUTF8MultibyteLen(ctxt, CUR_PTR,
// //                    "invalid character in attribute value\n");
// //            if (l == 0) {
// //                if (chunkSize > 0) {
// //                    xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //                    chunkSize = 0;
// //                }
// //                xmlSBufAddReplChar(&buf);
// //                NEXTL(1);
// //            } else {
// //                chunkSize += l;
// //                NEXTL(l);
// //            }
// //
// //            inSpace = 0;
// //        } else if (c != '&') {
// //            if (c > 0x20) {
// //                if (c == quote)
// //                    break;
// //
// //                if (c == '<')
// //                    xmlFatalErr(ctxt, XML_ERR_LT_IN_ATTRIBUTE, NULL);
// //
// //                chunkSize += 1;
// //                inSpace = 0;
// //            } else if (!IS_BYTE_CHAR(c)) {
// //                xmlFatalErrMsg(ctxt, XML_ERR_INVALID_CHAR,
// //                        "invalid character in attribute value\n");
// //                if (chunkSize > 0) {
// //                    xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //                    chunkSize = 0;
// //                }
// //                xmlSBufAddReplChar(&buf);
// //                inSpace = 0;
// //            } else {
// //                /* Whitespace */
// //                if ((normalize) && (inSpace)) {
// //                    /* Skip char */
// //                    if (chunkSize > 0) {
// //                        xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //                        chunkSize = 0;
// //                    }
// //                    attvalFlags |= XML_ATTVAL_NORM_CHANGE;
// //                } else if (c < 0x20) {
// //                    /* Convert to space */
// //                    if (chunkSize > 0) {
// //                        xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //                        chunkSize = 0;
// //                    }
// //
// //                    xmlSBufAddCString(&buf, " ", 1);
// //                } else {
// //                    chunkSize += 1;
// //                }
// //
// //                inSpace = 1;
// //
// //                if ((c == 0xD) && (NXT(1) == 0xA))
// //                    CUR_PTR++;
// //            }
// //
// //            NEXTL(1);
// //        } else if (NXT(1) == '#') {
// //            int val;
// //
// //            if (chunkSize > 0) {
// //                xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //                chunkSize = 0;
// //            }
// //
// //            val = xmlParseCharRef(ctxt);
// //            if (val == 0)
// //                goto error;
// //
// //            if ((val == '&') && (!replaceEntities)) {
// //                /*
// //                 * The reparsing will be done in xmlNodeParseContent()
// //                 * called from SAX2.c
// //                 */
// //                xmlSBufAddCString(&buf, "&#38;", 5);
// //                inSpace = 0;
// //            } else if (val == ' ') {
// //                if ((normalize) && (inSpace))
// //                    attvalFlags |= XML_ATTVAL_NORM_CHANGE;
// //                else
// //                    xmlSBufAddCString(&buf, " ", 1);
// //                inSpace = 1;
// //            } else {
// //                xmlSBufAddChar(&buf, val);
// //                inSpace = 0;
// //            }
// //        } else {
// //            const xmlChar *name;
// //            xmlEntityPtr ent;
// //
// //            if (chunkSize > 0) {
// //                xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //                chunkSize = 0;
// //            }
// //
// //            name = xmlParseEntityRefInternal(ctxt);
// //            if (name == NULL) {
// //                /*
// //                 * Probably a literal '&' which wasn't escaped.
// //                 * TODO: Handle gracefully in recovery mode.
// //                 */
// //                continue;
// //            }
// //
// //            ent = xmlLookupGeneralEntity(ctxt, name, /* isAttr */ 1);
// //            if (ent == NULL)
// //                continue;
// //
// //            if (ent->etype == XML_INTERNAL_PREDEFINED_ENTITY) {
// //                if ((ent->content[0] == '&') && (!replaceEntities))
// //                    xmlSBufAddCString(&buf, "&#38;", 5);
// //                else
// //                    xmlSBufAddString(&buf, ent->content, ent->length);
// //                inSpace = 0;
// //            } else if (replaceEntities) {
// //                if (xmlExpandEntityInAttValue(ctxt, &buf,
// //                        ent->content, ent, normalize, &inSpace, ctxt->inputNr,
// //                        /* check */ 1) > 0)
// //                    attvalFlags |= XML_ATTVAL_NORM_CHANGE;
// //            } else {
// //                if ((ent->flags & entFlags) != entFlags)
// //                    xmlCheckEntityInAttValue(ctxt, ent, ctxt->inputNr);
// //
// //                if (xmlParserEntityCheck(ctxt, ent->expandedSize)) {
// //                    ent->content[0] = 0;
// //                    goto error;
// //                }
// //
// //                /*
// //                 * Just output the reference
// //                 */
// //                xmlSBufAddCString(&buf, "&", 1);
// //                xmlSBufAddString(&buf, ent->name, xmlStrlen(ent->name));
// //                xmlSBufAddCString(&buf, ";", 1);
// //
// //                inSpace = 0;
// //            }
// //	}
// //    }
// //
// //    if ((buf.mem == NULL) && (outFlags != NULL)) {
// //        ret = (xmlChar *) CUR_PTR - chunkSize;
// //
// //        if (attlen != NULL)
// //            *attlen = chunkSize;
// //        if ((normalize) && (inSpace) && (chunkSize > 0)) {
// //            attvalFlags |= XML_ATTVAL_NORM_CHANGE;
// //            *attlen -= 1;
// //        }
// //
// //        /* Report potential error */
// //        xmlSBufCleanup(&buf, ctxt, "AttValue length too long");
// //    } else {
// //        if (chunkSize > 0)
// //            xmlSBufAddString(&buf, CUR_PTR - chunkSize, chunkSize);
// //
// //        if ((normalize) && (inSpace) && (buf.size > 0)) {
// //            attvalFlags |= XML_ATTVAL_NORM_CHANGE;
// //            buf.size--;
// //        }
// //
// //        ret = xmlSBufFinish(&buf, attlen, ctxt, "AttValue length too long");
// //        attvalFlags |= XML_ATTVAL_ALLOC;
// //
// //        if (ret != NULL) {
// //            if (attlen != NULL)
// //                *attlen = buf.size;
// //        }
// //    }
// //
// //    if (outFlags != NULL)
// //        *outFlags = attvalFlags;
// //
// //    NEXTL(1);
// //
// //    return(ret);
// //
// //error:
// //    xmlSBufCleanup(&buf, ctxt, "AttValue length too long");
// //    return(NULL);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlParseCharRef(xmlParserCtxt * ctxt);
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
#include <limits.h>

/* Use the absolute project header path found for xmlParseCharRef and helpers */
#include "/src/libxml2/include/libxml/parserInternals.h"

/* Fuzzer entry point expected by libFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic guards */
    if (Data == NULL || Size == 0) return 0;
    if (Size > (size_t)INT_MAX) return 0; /* xmlCreateMemoryParserCtxt takes an int size */

    /* Initialize global parser state (safe to call repeatedly) */
    xmlInitParser();

    /* Copy input into a buffer. xmlCreateMemoryParserCtxt accepts a buffer+size,
       but making a NUL-terminated copy can help subsystems that expect C-strings. */
    int bufSize = (int)Size;
    char *buf = (char *)malloc((size_t)bufSize + 1);
    if (buf == NULL) return 0;
    memcpy(buf, Data, (size_t)bufSize);
    buf[bufSize] = '\0';

    /* Create a parser context that uses the provided buffer as input */
    xmlParserCtxtPtr ctxt = xmlCreateMemoryParserCtxt(buf, bufSize);
    if (ctxt == NULL) {
        free(buf);
        return 0;
    }

    /* Call the target function under test.
       xmlParseCharRef expects the current input position to point at a character
       reference (typically starting with '&'). xmlCreateMemoryParserCtxt sets
       up the input->cur to the buffer start, so feeding arbitrary data is fine. */
    (void)xmlParseCharRef(ctxt);

    /* Clean up parser context and allocated buffer. */
    xmlFreeParserCtxt(ctxt);
    free(buf);

    /* Optionally cleanup global state (not strictly necessary for a single run,
       but harmless to call here). */
    /* xmlCleanupParser(); -- not called to avoid interfering with repeated runs in some harnesses */

    return 0;
}
