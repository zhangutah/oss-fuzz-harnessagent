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
// // xmlDtd *
// //xmlIOParseDTD(xmlSAXHandler *sax, xmlParserInputBuffer *input,
// //	      xmlCharEncoding enc) {
// //    xmlDtdPtr ret = NULL;
// //    xmlParserCtxtPtr ctxt;
// //    xmlParserInputPtr pinput = NULL;
// //
// //    if (input == NULL)
// //	return(NULL);
// //
// //    ctxt = xmlNewSAXParserCtxt(sax, NULL);
// //    if (ctxt == NULL) {
// //        xmlFreeParserInputBuffer(input);
// //	return(NULL);
// //    }
// //    xmlCtxtSetOptions(ctxt, XML_PARSE_DTDLOAD);
// //
// //    /*
// //     * generate a parser input from the I/O handler
// //     */
// //
// //    pinput = xmlNewIOInputStream(ctxt, input, XML_CHAR_ENCODING_NONE);
// //    if (pinput == NULL) {
// //        xmlFreeParserInputBuffer(input);
// //	xmlFreeParserCtxt(ctxt);
// //	return(NULL);
// //    }
// //
// //    if (enc != XML_CHAR_ENCODING_NONE) {
// //        xmlSwitchEncoding(ctxt, enc);
// //    }
// //
// //    ret = xmlCtxtParseDtd(ctxt, pinput, NULL, NULL);
// //
// //    xmlFreeParserCtxt(ctxt);
// //    return(ret);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     xmlDtd * xmlCtxtParseDtd(xmlParserCtxt * ctxt, xmlParserInput * input, const xmlChar * publicId, const xmlChar * systemId);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/xmlIO.h"
#include "/src/libxml2/include/libxml/tree.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/*
 Fuzzer driver for:
   xmlDtd * xmlCtxtParseDtd(xmlParserCtxt * ctxt,
                            xmlParserInput * input,
                            const xmlChar * publicId,
                            const xmlChar * systemId);

 Strategy:
 - Use the input Data as the memory backing for a parser input buffer
   (xmlParserInputBufferCreateMem) and build an xmlParserInput (xmlNewIOInputStream).
 - Derive optional small publicId and systemId strings from the Data bytes
   (first bytes indicate lengths). Allocate NUL-terminated copies for them.
 - Create a parser context (xmlNewParserCtxt), call xmlCtxtParseDtd and free
   resources. xmlCtxtParseDtd always frees the input stream passed to it.
*/

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize parser library (safe to call repeatedly) */
    xmlInitParser();

    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        xmlCleanupParser();
        return 0;
    }

    /* Clamp Size to int for xmlParserInputBufferCreateMem */
    int bufSize;
    if (Size > (size_t)INT_MAX) bufSize = INT_MAX;
    else bufSize = (int)Size;

    /* Create a parser input buffer from the raw data */
    xmlParserInputBufferPtr buf = xmlParserInputBufferCreateMem((const char *)Data, bufSize, XML_CHAR_ENCODING_NONE);
    if (buf == NULL) {
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Wrap the buffer into an xmlParserInput */
    xmlParserInputPtr input = xmlNewIOInputStream(ctxt, buf, XML_CHAR_ENCODING_NONE);
    if (input == NULL) {
        /* xmlNewIOInputStream failed: free buffer then exit */
        xmlFreeParserInputBuffer(buf);
        xmlFreeParserCtxt(ctxt);
        xmlCleanupParser();
        return 0;
    }

    /* Derive small publicId and systemId from the Data bytes.
       Layout:
         byte 0: pub_len (0..15)
         bytes [1 .. 1+pub_len-1] => publicId content
         byte (1+pub_len): sys_len (0..15)
         following bytes => systemId content
       If lengths can't be satisfied by Size, those ids are left NULL.
    */
    const xmlChar *publicId = NULL;
    const xmlChar *systemId = NULL;
    char *pub_copy = NULL;
    char *sys_copy = NULL;

    size_t pos = 0;
    if (Size >= 1) {
        uint8_t pub_len = Data[0] & 0x0F; /* limit to 0..15 */
        pos = 1;
        if (pub_len > 0 && Size >= pos + pub_len) {
            pub_copy = (char *)malloc((size_t)pub_len + 1);
            if (pub_copy) {
                memcpy(pub_copy, Data + pos, pub_len);
                pub_copy[pub_len] = '\0';
                publicId = (const xmlChar *)pub_copy;
            }
            pos += pub_len;
        }

        if (Size > pos) {
            uint8_t sys_len = Data[pos] & 0x0F;
            pos += 1;
            if (sys_len > 0 && Size >= pos + sys_len) {
                sys_copy = (char *)malloc((size_t)sys_len + 1);
                if (sys_copy) {
                    memcpy(sys_copy, Data + pos, sys_len);
                    sys_copy[sys_len] = '\0';
                    systemId = (const xmlChar *)sys_copy;
                }
            }
        }
    }

    /* Call target function. According to implementation comments,
       xmlCtxtParseDtd will free 'input' in any case. */
    xmlDtdPtr dtd = xmlCtxtParseDtd(ctxt, input, publicId, systemId);

    /* Free returned DTD if non-NULL */
    if (dtd != NULL) {
        xmlFreeDtd(dtd);
    }

    /* Free allocated id copies */
    if (pub_copy) free(pub_copy);
    if (sys_copy) free(sys_copy);

    /* Free parser context and cleanup */
    xmlFreeParserCtxt(ctxt);
    xmlCleanupParser();

    return 0;
}
