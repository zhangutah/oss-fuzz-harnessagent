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
// // static xmlXPathCompExprPtr
// //xmlXPathTryStreamCompile(xmlXPathContextPtr ctxt, const xmlChar *str) {
// //    /*
// //     * Optimization: use streaming patterns when the XPath expression can
// //     * be compiled to a stream lookup
// //     */
// //    xmlPatternPtr stream;
// //    xmlXPathCompExprPtr comp;
// //    xmlDictPtr dict = NULL;
// //    const xmlChar **namespaces = NULL;
// //    xmlNsPtr ns;
// //    int i, j;
// //
// //    if ((!xmlStrchr(str, '[')) && (!xmlStrchr(str, '(')) &&
// //        (!xmlStrchr(str, '@'))) {
// //	const xmlChar *tmp;
// //        int res;
// //
// //	/*
// //	 * We don't try to handle expressions using the verbose axis
// //	 * specifiers ("::"), just the simplified form at this point.
// //	 * Additionally, if there is no list of namespaces available and
// //	 *  there's a ":" in the expression, indicating a prefixed QName,
// //	 *  then we won't try to compile either. xmlPatterncompile() needs
// //	 *  to have a list of namespaces at compilation time in order to
// //	 *  compile prefixed name tests.
// //	 */
// //	tmp = xmlStrchr(str, ':');
// //	if ((tmp != NULL) &&
// //	    ((ctxt == NULL) || (ctxt->nsNr == 0) || (tmp[1] == ':')))
// //	    return(NULL);
// //
// //	if (ctxt != NULL) {
// //	    dict = ctxt->dict;
// //	    if (ctxt->nsNr > 0) {
// //		namespaces = xmlMalloc(2 * (ctxt->nsNr + 1) * sizeof(xmlChar*));
// //		if (namespaces == NULL) {
// //		    xmlXPathErrMemory(ctxt);
// //		    return(NULL);
// //		}
// //		for (i = 0, j = 0; (j < ctxt->nsNr); j++) {
// //		    ns = ctxt->namespaces[j];
// //		    namespaces[i++] = ns->href;
// //		    namespaces[i++] = ns->prefix;
// //		}
// //		namespaces[i++] = NULL;
// //		namespaces[i] = NULL;
// //	    }
// //	}
// //
// //	res = xmlPatternCompileSafe(str, dict, XML_PATTERN_XPATH, namespaces,
// //                                    &stream);
// //	if (namespaces != NULL) {
// //	    xmlFree((xmlChar **)namespaces);
// //	}
// //        if (res < 0) {
// //            xmlXPathErrMemory(ctxt);
// //            return(NULL);
// //        }
// //	if ((stream != NULL) && (xmlPatternStreamable(stream) == 1)) {
// //	    comp = xmlXPathNewCompExpr();
// //	    if (comp == NULL) {
// //		xmlXPathErrMemory(ctxt);
// //	        xmlFreePattern(stream);
// //		return(NULL);
// //	    }
// //	    comp->stream = stream;
// //	    comp->dict = dict;
// //	    if (comp->dict)
// //		xmlDictReference(comp->dict);
// //	    return(comp);
// //	}
// //	xmlFreePattern(stream);
// //    }
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
//     int xmlPatternCompileSafe(const xmlChar * pattern, xmlDict * dict, int flags, const xmlChar ** namespaces, xmlPattern ** patternOut);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for xmlPatternCompileSafe from libxml2
// Build with: clang -fsanitize=fuzzer,address -I/path/to/libxml2/include driver.c -lxml2
// The fuzzer entry point: LLVMFuzzerTestOneInput

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/pattern.h>
#include <libxml/dict.h>
#include <libxml/parser.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Basic guard
    if (Data == NULL || Size == 0)
        return 0;

    // Initialize libxml parser subsystem once (idempotent)
    xmlInitParser();

    // Cap allocation sizes to avoid extreme memory use from malformed inputs
    size_t cap = 1 << 20; // 1MB cap
    size_t len = Size;
    if (len > cap) len = cap;

    // Prepare a null-terminated pattern string (xmlChar is unsigned char)
    xmlChar *pattern = (xmlChar *)malloc(len + 1);
    if (pattern == NULL)
        return 0;
    memcpy(pattern, Data, len);
    pattern[len] = '\0';

    // Create a dictionary for use by xmlPatternCompileSafe
    xmlDictPtr dict = xmlDictCreate();
    // dict may be NULL on allocation failure, handle gracefully by passing NULL

    // Prepare flags derived from input to explore different code paths.
    // Use lower bits of first byte to map to xmlPatternFlags bits.
    int flags = 0;
#ifdef XML_PATTERN_XPATH
    // Map bits from Data[0] into known flags if available
    flags = (int)(Data[0]) & (XML_PATTERN_XPATH | XML_PATTERN_XSSEL | XML_PATTERN_XSFIELD);
#else
    (void)flags;
#endif

    // Optionally prepare a single namespace pair from the remaining input.
    // The namespaces parameter expects an array of xmlChar* like [URI, prefix, NULL] or NULL.
    const xmlChar **namespaces = NULL;
    xmlChar *ns_uri = NULL;
    xmlChar *ns_prefix = NULL;
    const xmlChar *ns_array[3] = { NULL, NULL, NULL };

    if (Size >= 2) {
        // Split the available data (up to len) into two parts for URI and prefix.
        size_t half = len / 2;
        size_t uri_len = (half > 0) ? half : 1;
        size_t prefix_len = (len - half > 0) ? (len - half) : 1;

        ns_uri = (xmlChar *)malloc(uri_len + 1);
        ns_prefix = (xmlChar *)malloc(prefix_len + 1);

        if (ns_uri != NULL && ns_prefix != NULL) {
            memcpy(ns_uri, Data, uri_len);
            ns_uri[uri_len] = '\0';
            memcpy(ns_prefix, Data + uri_len, prefix_len);
            ns_prefix[prefix_len] = '\0';

            ns_array[0] = (const xmlChar *)ns_uri;
            ns_array[1] = (const xmlChar *)ns_prefix;
            ns_array[2] = NULL;
            namespaces = ns_array;
        } else {
            // If allocation failed, ensure we free any partial allocations and proceed with NULL namespaces
            free(ns_uri);
            free(ns_prefix);
            ns_uri = ns_prefix = NULL;
            namespaces = NULL;
        }
    }

    // Output pattern pointer
    xmlPattern *compiled = NULL;

    // Call the target function under test
    // xmlPatternCompileSafe returns 0 on success, 1 on error, -1 on memory allocation failure.
    // We call it with our fuzzed inputs.
    (void) xmlPatternCompileSafe((const xmlChar *)pattern, dict, flags, namespaces, &compiled);

    // If compilation produced a pattern, free it
    if (compiled != NULL) {
        xmlFreePattern(compiled);
        compiled = NULL;
    }

    // Free dictionary
    if (dict != NULL) {
        xmlDictFree(dict);
        dict = NULL;
    }

    // Free allocated namespace strings and pattern
    if (ns_uri) free(ns_uri);
    if (ns_prefix) free(ns_prefix);
    if (pattern) free(pattern);

    // Note: Do not call xmlCleanupParser() here because the fuzzer will invoke this function
    // repeatedly; global cleanup between runs may be handled externally if desired.

    return 0;
}
