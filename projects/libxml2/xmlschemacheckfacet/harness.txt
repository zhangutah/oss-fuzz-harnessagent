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
// // static int
// //xmlRelaxNGSchemaFacetCheck(void *data ATTRIBUTE_UNUSED,
// //                           const xmlChar * type, const xmlChar * facetname,
// //                           const xmlChar * val, const xmlChar * strval,
// //                           void *value)
// //{
// //    xmlSchemaFacetPtr facet;
// //    xmlSchemaTypePtr typ;
// //    int ret;
// //
// //    if ((type == NULL) || (strval == NULL))
// //        return (-1);
// //    typ = xmlSchemaGetPredefinedType(type,
// //                                     BAD_CAST
// //                                     "http://www.w3.org/2001/XMLSchema");
// //    if (typ == NULL)
// //        return (-1);
// //
// //    facet = xmlSchemaNewFacet();
// //    if (facet == NULL)
// //        return (-1);
// //
// //    if (xmlStrEqual(facetname, BAD_CAST "minInclusive")) {
// //        facet->type = XML_SCHEMA_FACET_MININCLUSIVE;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "minExclusive")) {
// //        facet->type = XML_SCHEMA_FACET_MINEXCLUSIVE;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "maxInclusive")) {
// //        facet->type = XML_SCHEMA_FACET_MAXINCLUSIVE;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "maxExclusive")) {
// //        facet->type = XML_SCHEMA_FACET_MAXEXCLUSIVE;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "totalDigits")) {
// //        facet->type = XML_SCHEMA_FACET_TOTALDIGITS;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "fractionDigits")) {
// //        facet->type = XML_SCHEMA_FACET_FRACTIONDIGITS;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "pattern")) {
// //        facet->type = XML_SCHEMA_FACET_PATTERN;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "enumeration")) {
// //        facet->type = XML_SCHEMA_FACET_ENUMERATION;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "whiteSpace")) {
// //        facet->type = XML_SCHEMA_FACET_WHITESPACE;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "length")) {
// //        facet->type = XML_SCHEMA_FACET_LENGTH;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "maxLength")) {
// //        facet->type = XML_SCHEMA_FACET_MAXLENGTH;
// //    } else if (xmlStrEqual(facetname, BAD_CAST "minLength")) {
// //        facet->type = XML_SCHEMA_FACET_MINLENGTH;
// //    } else {
// //        xmlSchemaFreeFacet(facet);
// //        return (-1);
// //    }
// //    facet->value = val;
// //    ret = xmlSchemaCheckFacet(facet, typ, NULL, type);
// //    if (ret != 0) {
// //        xmlSchemaFreeFacet(facet);
// //        return (-1);
// //    }
// //    ret = xmlSchemaValidateFacet(typ, facet, strval, value);
// //    xmlSchemaFreeFacet(facet);
// //    if (ret != 0)
// //        return (-1);
// //    return (0);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlSchemaCheckFacet(xmlSchemaFacet * facet, xmlSchemaType * typeDecl, xmlSchemaParserCtxt * ctxt, const xmlChar * name);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for xmlSchemaCheckFacet
// Build-time assumptions: this is compiled and linked with the libxml2 sources/libraries
// and the libxml2 headers are available under <libxml/...>.
//
// The fuzzer entry point: LLVMFuzzerTestOneInput
//
// Strategy:
// - Use the first input byte to select a facet type handled by xmlSchemaCheckFacet.
// - Use the remaining bytes as a UTF-8/byte string for the facet value.
// - Pick a reasonable built-in type for the facet (string or integer variants).
// - Create an xmlSchemaFacet with xmlSchemaNewFacet(), populate fields, and call
//   xmlSchemaCheckFacet(facet, typeDecl, NULL, NULL).
// - Clean up allocated resources.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>               // xmlInitParser()
#include <libxml/xmlversion.h>
#include <libxml/xmlschemastypes.h>      // xmlSchema* APIs
#include <libxml/schemasInternals.h>     // internal typedefs/enums (available in tree build)

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size < 1)
        return 0;

    // Initialize libxml2 parser state (safe to call multiple times)
    xmlInitParser();

    // Map of facet types we want to exercise (subset handled by xmlSchemaCheckFacet).
    // We'll choose one based on the first byte of input.
    const int facetTypes[] = {
        XML_SCHEMA_FACET_MININCLUSIVE,
        XML_SCHEMA_FACET_MINEXCLUSIVE,
        XML_SCHEMA_FACET_MAXINCLUSIVE,
        XML_SCHEMA_FACET_MAXEXCLUSIVE,
        XML_SCHEMA_FACET_ENUMERATION,
        XML_SCHEMA_FACET_PATTERN,
        XML_SCHEMA_FACET_TOTALDIGITS,
        XML_SCHEMA_FACET_FRACTIONDIGITS,
        XML_SCHEMA_FACET_LENGTH,
        XML_SCHEMA_FACET_MAXLENGTH,
        XML_SCHEMA_FACET_MINLENGTH,
        XML_SCHEMA_FACET_WHITESPACE
    };
    const size_t facetCount = sizeof(facetTypes) / sizeof(facetTypes[0]);

    // Choose facet type from first byte
    unsigned int choice = Data[0];
    int chosenFacet = facetTypes[choice % facetCount];

    // Prepare facet value string from remaining input bytes.
    // If there are no remaining bytes, use a short constant string.
    const size_t valSize = (Size > 1) ? (Size - 1) : 1;
    char *valBuf = (char *)malloc(valSize + 1);
    if (!valBuf) return 0;
    if (Size > 1) {
        memcpy(valBuf, Data + 1, valSize);
    } else {
        // minimal content
        valBuf[0] = 'a';
    }
    valBuf[valSize] = '\0';

    // Create facet object
    xmlSchemaFacetPtr facet = xmlSchemaNewFacet();
    if (facet == NULL) {
        free(valBuf);
        return 0;
    }

    // Fill the facet struct fields we need
    facet->type = chosenFacet;
    // xmlSchemaCheckFacet expects facet->value as an xmlChar* (unsigned char*)
    facet->value = (const xmlChar *)valBuf;
    facet->node = NULL; // we don't have a node context in this fuzzer

    // Select a built-in type appropriate for the chosen facet.
    // xmlSchemaGetBuiltInType expects an xmlSchemaValType enum value.
    xmlSchemaTypePtr typeDecl = NULL;
    switch (chosenFacet) {
        case XML_SCHEMA_FACET_PATTERN:
        case XML_SCHEMA_FACET_WHITESPACE:
        case XML_SCHEMA_FACET_ENUMERATION:
            // String-like facets
            typeDecl = xmlSchemaGetBuiltInType(XML_SCHEMAS_STRING);
            break;
        case XML_SCHEMA_FACET_TOTALDIGITS:
            // per xmlschemas.c, TOTALDIGITS uses positiveInteger (PINTEGER)
            typeDecl = xmlSchemaGetBuiltInType(XML_SCHEMAS_PINTEGER);
            break;
        case XML_SCHEMA_FACET_FRACTIONDIGITS:
        case XML_SCHEMA_FACET_LENGTH:
        case XML_SCHEMA_FACET_MAXLENGTH:
        case XML_SCHEMA_FACET_MINLENGTH:
            // non-negative integer used for many length-related facets
            typeDecl = xmlSchemaGetBuiltInType(XML_SCHEMAS_NNINTEGER);
            break;
        case XML_SCHEMA_FACET_MININCLUSIVE:
        case XML_SCHEMA_FACET_MINEXCLUSIVE:
        case XML_SCHEMA_FACET_MAXINCLUSIVE:
        case XML_SCHEMA_FACET_MAXEXCLUSIVE:
        default:
            // numeric or general: try integer as a common case
            typeDecl = xmlSchemaGetBuiltInType(XML_SCHEMAS_INTEGER);
            break;
    }

    // Call the target function. We pass pctxt = NULL and name = NULL to exercise the
    // code path that may create a parser context internally.
    (void)xmlSchemaCheckFacet(facet, typeDecl, NULL, NULL);

    // Cleanup: xmlSchemaFreeFacet should free the facet structure and associated compiled value.
    xmlSchemaFreeFacet(facet);

    // valBuf was assigned to facet->value (const xmlChar *) which is not owned by facet->value;
    // xmlSchemaFreeFacet does not free the original string we passed. Free now.
    free(valBuf);

    // Optionally cleanup libxml parser global state (not strictly necessary per fuzzer runs)
    // xmlCleanupParser(); // avoid calling frequently in long-running fuzz loop

    return 0;
}
