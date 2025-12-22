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
//     void xmlXPathDivValues(xmlXPathParserContext * ctxt);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Include internal headers so we can construct xmlXPathParserContext and
 * xmlXPathObject structures directly and call the internal API used by
 * xmlXPathDivValues.
 *
 * Using the project absolute header path as discovered in the codebase.
 */
#include "/src/libxml2/include/libxml/xpathInternals.h"
#include "/src/libxml2/include/libxml/xpath.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/*
 * The target function to fuzz:
 *   void xmlXPathDivValues(xmlXPathParserContext * ctxt);
 *
 * Fuzzer entry point required by libFuzzer:
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Defensive: need at least some bytes, but we can handle smaller sizes. */
    double num_val = 0.0;  /* numerator */
    double div_val = 1.0;  /* divisor (avoid implicit divide-by-zero as a default) */

    /* Fill our two doubles from the fuzzer input if available. */
    if (Size >= sizeof(double)) {
        /* Use first bytes for divisor */
        memcpy(&div_val, Data, sizeof(double));
    } else if (Size > 0) {
        /* If fewer than 8 bytes, expand deterministically */
        uint8_t buf[8] = {0};
        memcpy(buf, Data, Size);
        memcpy(&div_val, buf, sizeof(double));
    }

    if (Size >= 2 * sizeof(double)) {
        memcpy(&num_val, Data + sizeof(double), sizeof(double));
    } else if (Size > sizeof(double)) {
        size_t rem = Size - sizeof(double);
        uint8_t buf[8] = {0};
        memcpy(buf, Data + sizeof(double), rem);
        memcpy(&num_val, buf, sizeof(double));
    } else {
        /* If only small input, derive numerator from divisor to vary testcases */
        num_val = div_val * 2.0 + 1.0;
    }

    /*
     * Construct a minimal xmlXPathParserContext compatible with
     * xmlXPathDivValues. The function expects the parser stack to hold two
     * values: [ numerator, divisor ] with valueNr==2 and ctxt->value pointing
     * at the top (divisor) before the pop.
     *
     * We'll allocate xmlXPathObject structures for numerator and divisor and
     * set their types to XPATH_NUMBER so no complex casting is needed.
     */

    xmlXPathParserContext ctxt_storage;
    memset(&ctxt_storage, 0, sizeof(ctxt_storage));

    /* Make sure context->context is NULL so xmlXPathReleaseObject will fall
     * back to xmlXPathFreeObject(obj). This avoids needing a full xmlXPathContext.
     */
    ctxt_storage.context = NULL;

    /* Prepare value stack of 2 entries */
    const int stackSize = 2;
    xmlXPathObjectPtr *valTab = (xmlXPathObjectPtr *) xmlMalloc(stackSize * sizeof(xmlXPathObjectPtr));
    if (valTab == NULL) {
        return 0;
    }
    memset(valTab, 0, stackSize * sizeof(xmlXPathObjectPtr));
    ctxt_storage.valueTab = valTab;
    ctxt_storage.valueMax = stackSize;

    /* Allocate divisor object (top of stack) */
    xmlXPathObjectPtr divisor = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (divisor == NULL) {
        xmlFree(valTab);
        return 0;
    }
    memset(divisor, 0, sizeof(*divisor));
    divisor->type = XPATH_NUMBER;
    divisor->floatval = div_val;

    /* Allocate numerator object (below top) */
    xmlXPathObjectPtr numerator = (xmlXPathObjectPtr) xmlMalloc(sizeof(xmlXPathObject));
    if (numerator == NULL) {
        xmlFree(divisor);
        xmlFree(valTab);
        return 0;
    }
    memset(numerator, 0, sizeof(*numerator));
    numerator->type = XPATH_NUMBER;
    numerator->floatval = num_val;

    /*
     * Stack layout:
     *   valueTab[0] = numerator
     *   valueTab[1] = divisor  (top)
     * valueNr = 2
     * ctxt->value should point to top (divisor) initially.
     */
    valTab[0] = numerator;
    valTab[1] = divisor;
    ctxt_storage.valueNr = 2;
    ctxt_storage.value = divisor;

    /*
     * Now call the function under test.
     * It will pop the divisor, cast it to number (we already used XPATH_NUMBER),
     * CAST_TO_NUMBER will convert numerator to number if needed (it's already),
     * and then perform numerator->floatval /= val.
     *
     * Note: xmlXPathDivValues expects an xmlXPathParserContext*, which we
     * provide.
     */
    xmlXPathDivValues(&ctxt_storage);

    /*
     * Clean up:
     * - After xmlXPathDivValues returns, the divisor (arg) has been released by
     *   xmlXPathReleaseObject(ctxt->context, arg); since ctxt->context==NULL this
     *   results in xmlXPathFreeObject(arg) -> xmlFree(arg). So divisor might
     *   already be freed. To be safe, avoid double-free by checking whether
     *   valueTab[1] was nulled by xmlXPathValuePop (it sets the popped slot to NULL).
     *
     * - The remaining value (the result) is at valueTab[0] (numerator). Free it.
     */

    if (ctxt_storage.valueTab != NULL) {
        /* Free remaining objects referenced in the stack (if any). */
        for (int i = 0; i < ctxt_storage.valueMax; ++i) {
            xmlXPathObjectPtr obj = ctxt_storage.valueTab[i];
            if (obj != NULL) {
                /* Use xmlXPathFreeObject to free an xmlXPathObject */
                xmlXPathFreeObject(obj);
                ctxt_storage.valueTab[i] = NULL;
            }
        }
        xmlFree(ctxt_storage.valueTab);
        ctxt_storage.valueTab = NULL;
    }

    return 0;
}