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
// //xmlNodeDumpOutputInternal(xmlSaveCtxtPtr ctxt, xmlNodePtr cur) {
// //    int format = ctxt->format;
// //    xmlNodePtr tmp, root, unformattedNode = NULL, parent;
// //    xmlAttrPtr attr;
// //    xmlChar *start, *end;
// //    xmlOutputBufferPtr buf;
// //
// //    if (cur == NULL) return;
// //    buf = ctxt->buf;
// //
// //    root = cur;
// //    parent = cur->parent;
// //    while (1) {
// //        switch (cur->type) {
// //        case XML_DOCUMENT_NODE:
// //        case XML_HTML_DOCUMENT_NODE:
// //	    xmlSaveDocInternal(ctxt, (xmlDocPtr) cur, ctxt->encoding);
// //	    break;
// //
// //        case XML_DTD_NODE:
// //            xmlDtdDumpOutput(ctxt, (xmlDtdPtr) cur);
// //            break;
// //
// //        case XML_DOCUMENT_FRAG_NODE:
// //            /* Always validate cur->parent when descending. */
// //            if ((cur->parent == parent) && (cur->children != NULL)) {
// //                parent = cur;
// //                cur = cur->children;
// //                continue;
// //            }
// //	    break;
// //
// //        case XML_ELEMENT_DECL:
// //            xmlBufDumpElementDecl(buf, (xmlElementPtr) cur);
// //            break;
// //
// //        case XML_ATTRIBUTE_DECL:
// //            xmlSaveWriteAttributeDecl(ctxt, (xmlAttributePtr) cur);
// //            break;
// //
// //        case XML_ENTITY_DECL:
// //            xmlBufDumpEntityDecl(buf, (xmlEntityPtr) cur);
// //            break;
// //
// //        case XML_ELEMENT_NODE:
// //	    if ((cur != root) && (ctxt->format == 1))
// //                xmlSaveWriteIndent(ctxt, 0);
// //
// //            /*
// //             * Some users like lxml are known to pass nodes with a corrupted
// //             * tree structure. Fall back to a recursive call to handle this
// //             * case.
// //             */
// //            if ((cur->parent != parent) && (cur->children != NULL)) {
// //                xmlNodeDumpOutputInternal(ctxt, cur);
// //                break;
// //            }
// //
// //            xmlOutputBufferWrite(buf, 1, "<");
// //            if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
// //                xmlOutputBufferWriteString(buf, (const char *)cur->ns->prefix);
// //                xmlOutputBufferWrite(buf, 1, ":");
// //            }
// //            xmlOutputBufferWriteString(buf, (const char *)cur->name);
// //            if (cur->nsDef)
// //                xmlNsListDumpOutputCtxt(ctxt, cur->nsDef);
// //            for (attr = cur->properties; attr != NULL; attr = attr->next)
// //                xmlAttrDumpOutput(ctxt, attr);
// //
// //            if (cur->children == NULL) {
// //                if ((ctxt->options & XML_SAVE_NO_EMPTY) == 0) {
// //                    if (ctxt->format == 2)
// //                        xmlOutputBufferWriteWSNonSig(ctxt, 0);
// //                    xmlOutputBufferWrite(buf, 2, "/>");
// //                } else {
// //                    if (ctxt->format == 2)
// //                        xmlOutputBufferWriteWSNonSig(ctxt, 1);
// //                    xmlOutputBufferWrite(buf, 3, "></");
// //                    if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
// //                        xmlOutputBufferWriteString(buf,
// //                                (const char *)cur->ns->prefix);
// //                        xmlOutputBufferWrite(buf, 1, ":");
// //                    }
// //                    xmlOutputBufferWriteString(buf, (const char *)cur->name);
// //                    if (ctxt->format == 2)
// //                        xmlOutputBufferWriteWSNonSig(ctxt, 0);
// //                    xmlOutputBufferWrite(buf, 1, ">");
// //                }
// //            } else {
// //                if (ctxt->format == 1) {
// //                    tmp = cur->children;
// //                    while (tmp != NULL) {
// //                        if ((tmp->type == XML_TEXT_NODE) ||
// //                            (tmp->type == XML_CDATA_SECTION_NODE) ||
// //                            (tmp->type == XML_ENTITY_REF_NODE)) {
// //                            ctxt->format = 0;
// //                            unformattedNode = cur;
// //                            break;
// //                        }
// //                        tmp = tmp->next;
// //                    }
// //                }
// //                if (ctxt->format == 2)
// //                    xmlOutputBufferWriteWSNonSig(ctxt, 1);
// //                xmlOutputBufferWrite(buf, 1, ">");
// //                if (ctxt->format == 1) xmlOutputBufferWrite(buf, 1, "\n");
// //                if (ctxt->level >= 0) ctxt->level++;
// //                parent = cur;
// //                cur = cur->children;
// //                continue;
// //            }
// //
// //            break;
// //
// //        case XML_TEXT_NODE:
// //	    if (cur->content == NULL)
// //                break;
// //	    if (cur->name != xmlStringTextNoenc) {
// //                if (ctxt->escape)
// //                    xmlOutputBufferWriteEscape(buf, cur->content,
// //                                               ctxt->escape);
// //#ifdef TEST_OUTPUT_BUFFER_WRITE_ESCAPE
// //                else if (ctxt->encoding)
// //                    xmlOutputBufferWriteEscape(buf, cur->content, NULL);
// //#endif
// //                else
// //                    xmlSaveWriteText(ctxt, cur->content, /* flags */ 0);
// //	    } else {
// //		/*
// //		 * Disable escaping, needed for XSLT
// //		 */
// //		xmlOutputBufferWriteString(buf, (const char *) cur->content);
// //	    }
// //	    break;
// //
// //        case XML_PI_NODE:
// //	    if ((cur != root) && (ctxt->format == 1))
// //                xmlSaveWriteIndent(ctxt, 0);
// //
// //            if (cur->content != NULL) {
// //                xmlOutputBufferWrite(buf, 2, "<?");
// //                xmlOutputBufferWriteString(buf, (const char *)cur->name);
// //                if (cur->content != NULL) {
// //                    if (ctxt->format == 2)
// //                        xmlOutputBufferWriteWSNonSig(ctxt, 0);
// //                    else
// //                        xmlOutputBufferWrite(buf, 1, " ");
// //                    xmlOutputBufferWriteString(buf,
// //                            (const char *)cur->content);
// //                }
// //                xmlOutputBufferWrite(buf, 2, "?>");
// //            } else {
// //                xmlOutputBufferWrite(buf, 2, "<?");
// //                xmlOutputBufferWriteString(buf, (const char *)cur->name);
// //                if (ctxt->format == 2)
// //                    xmlOutputBufferWriteWSNonSig(ctxt, 0);
// //                xmlOutputBufferWrite(buf, 2, "?>");
// //            }
// //            break;
// //
// //        case XML_COMMENT_NODE:
// //	    if ((cur != root) && (ctxt->format == 1))
// //                xmlSaveWriteIndent(ctxt, 0);
// //
// //            if (cur->content != NULL) {
// //                xmlOutputBufferWrite(buf, 4, "<!--");
// //                xmlOutputBufferWriteString(buf, (const char *)cur->content);
// //                xmlOutputBufferWrite(buf, 3, "-->");
// //            }
// //            break;
// //
// //        case XML_ENTITY_REF_NODE:
// //            xmlOutputBufferWrite(buf, 1, "&");
// //            xmlOutputBufferWriteString(buf, (const char *)cur->name);
// //            xmlOutputBufferWrite(buf, 1, ";");
// //            break;
// //
// //        case XML_CDATA_SECTION_NODE:
// //            if (cur->content == NULL || *cur->content == '\0') {
// //                xmlOutputBufferWrite(buf, 12, "<![CDATA[]]>");
// //            } else {
// //                start = end = cur->content;
// //                while (*end != '\0') {
// //                    if ((*end == ']') && (*(end + 1) == ']') &&
// //                        (*(end + 2) == '>')) {
// //                        end = end + 2;
// //                        xmlOutputBufferWrite(buf, 9, "<![CDATA[");
// //                        xmlOutputBufferWrite(buf, end - start,
// //                                (const char *)start);
// //                        xmlOutputBufferWrite(buf, 3, "]]>");
// //                        start = end;
// //                    }
// //                    end++;
// //                }
// //                if (start != end) {
// //                    xmlOutputBufferWrite(buf, 9, "<![CDATA[");
// //                    xmlOutputBufferWriteString(buf, (const char *)start);
// //                    xmlOutputBufferWrite(buf, 3, "]]>");
// //                }
// //            }
// //            break;
// //
// //        case XML_ATTRIBUTE_NODE:
// //            xmlAttrDumpOutput(ctxt, (xmlAttrPtr) cur);
// //            break;
// //
// //        case XML_NAMESPACE_DECL:
// //            xmlNsDumpOutput(buf, (xmlNsPtr) cur, ctxt);
// //            break;
// //
// //        default:
// //            break;
// //        }
// //
// //        while (1) {
// //            if (cur == root)
// //                return;
// //            if ((ctxt->format == 1) &&
// //                (cur->type != XML_XINCLUDE_START) &&
// //                (cur->type != XML_XINCLUDE_END))
// //                xmlOutputBufferWrite(buf, 1, "\n");
// //            if (cur->next != NULL) {
// //                cur = cur->next;
// //                break;
// //            }
// //
// //            cur = parent;
// //            /* cur->parent was validated when descending. */
// //            parent = cur->parent;
// //
// //            if (cur->type == XML_ELEMENT_NODE) {
// //                if (ctxt->level > 0) ctxt->level--;
// //                if (ctxt->format == 1)
// //                    xmlSaveWriteIndent(ctxt, 0);
// //
// //                xmlOutputBufferWrite(buf, 2, "</");
// //                if ((cur->ns != NULL) && (cur->ns->prefix != NULL)) {
// //                    xmlOutputBufferWriteString(buf,
// //                            (const char *)cur->ns->prefix);
// //                    xmlOutputBufferWrite(buf, 1, ":");
// //                }
// //
// //                xmlOutputBufferWriteString(buf, (const char *)cur->name);
// //                if (ctxt->format == 2)
// //                    xmlOutputBufferWriteWSNonSig(ctxt, 0);
// //                xmlOutputBufferWrite(buf, 1, ">");
// //
// //                if (cur == unformattedNode) {
// //                    ctxt->format = format;
// //                    unformattedNode = NULL;
// //                }
// //            }
// //        }
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
//     int xmlOutputBufferWriteEscape(xmlOutputBuffer * out, const xmlChar * str, xmlCharEncodingOutputFunc escaping);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for:
//   int xmlOutputBufferWriteEscape(xmlOutputBuffer * out, const xmlChar * str, xmlCharEncodingOutputFunc escaping);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// To compile this against the project's libxml2 sources, use the project's include paths and link with the built libxml2 objects.
// Example (adjust include/lib paths & link flags to your build):
//   clang -g -O1 -fsanitize=fuzzer,address -I/path/to/libxml2/include fuzz_xmlOutputBufferWriteEscape.c -L/path/to/libxml2/.libs -lxml2
//
// This driver creates an xmlOutputBuffer via xmlAllocOutputBuffer(NULL),
// constructs a NUL-terminated copy of the fuzzer input (xmlChar*), and calls
// xmlOutputBufferWriteEscape with a small passthrough encoding callback.
// The buffer is then closed.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlIO.h>
#include <libxml/encoding.h>

// A simple encoding callback that just copies as much as possible from `in` to `out`.
// Conforms to xmlCharEncodingOutputFunc:
//   int fn(unsigned char *out, int *outlen, const unsigned char *in, int *inlen);
// On success it returns the number of bytes written and sets *outlen to produced bytes
// and *inlen to consumed bytes.
static int
passthrough_encoding(unsigned char *out, int *outlen,
                     const unsigned char *in, int *inlen) {
    if (out == NULL || outlen == NULL || in == NULL || inlen == NULL)
        return XML_ENC_ERR_INTERNAL;

    int avail_out = *outlen;
    int avail_in = *inlen;

    if (avail_out <= 0 || avail_in <= 0) {
        // No space or no input: nothing consumed/produced.
        *outlen = 0;
        *inlen = 0;
        return XML_ENC_ERR_SPACE;
    }

    int tocopy = avail_out < avail_in ? avail_out : avail_in;
    memcpy(out, in, (size_t)tocopy);

    // According to the xmlCharEncodingOutputFunc contract, set outlen to number produced
    // and inlen to number consumed.
    *outlen = tocopy;
    *inlen = tocopy;
    return tocopy;
}

// Fuzzer entry point.
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Defensive: nothing to do for empty input.
    if (Data == NULL || Size == 0)
        return 0;

    // Create a NUL-terminated copy of the input because xmlOutputBufferWriteEscape
    // expects a C-style string (const xmlChar *).
    // Use malloc/free to avoid depending on libxml allocators here.
    size_t bufSize = Size + 1;
    unsigned char *str = (unsigned char *)malloc(bufSize);
    if (str == NULL)
        return 0;
    memcpy(str, Data, Size);
    str[Size] = 0; // NUL-terminate

    // Allocate an output buffer with default encoding (NULL).
    xmlOutputBufferPtr out = xmlAllocOutputBuffer(NULL);
    if (out == NULL) {
        free(str);
        return 0;
    }

    // Call the target function with our passthrough encoding callback.
    // The function will use the NUL-terminated string; binary data with embedded NULs
    // will stop at the first NUL, but that's acceptable for this harness.
    (void)xmlOutputBufferWriteEscape(out, (const xmlChar *)str, passthrough_encoding);

    // Close and free the output buffer.
    // xmlOutputBufferClose flushes and frees internal structures.
    (void)xmlOutputBufferClose(out);

    free(str);
    return 0;
}
