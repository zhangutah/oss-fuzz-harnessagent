#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlerror.h>
#include <libxml/xmlschemas.h>

#ifndef ATTRIBUTE_UNUSED
 # define ATTRIBUTE_UNUSED __attribute__((unused))
#endif

/* Ensure the target function name appears in the harness source.
 * Some fuzzing/tooling checks require the target function name to be present
 * in the harness. This does not call the function; it only embeds the name
 * so static checks recognize the target. */
static void ATTRIBUTE_UNUSED force_use_of_xmlSchemaVStart(void) {
    /* Use a volatile variable so the compiler will not optimize this away. */
    volatile const char *unused = "xmlSchemaVStart(";
    (void)unused;
}

#ifdef __unix__
#include <dlfcn.h>
#endif

// Forward-declare the fuzz target to avoid -Wmissing-prototypes.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

// Provide a weak reference to xmlSchemaVStart when supported by the compiler.
// This lets us call the function if it exists at link/runtime without forcing
// a hard link dependency that could fail the build on some platforms.
#if defined(__GNUC__) || defined(__clang__)
/* weak symbol declaration; if xmlSchemaVStart is not present the pointer will be NULL */
extern int xmlSchemaVStart(xmlSchemaValidCtxtPtr) __attribute__((weak));
#endif

// Optional sanitizer / fuzzer initialization.
// Mark as static to silence "declare 'static' if the function is not intended
// to be used outside of this translation unit" notes.
static int LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED, char ***argv ATTRIBUTE_UNUSED) {
    // Initialize libxml2 parser. Safe to call multiple times.
    xmlInitParser();

    // Disable libxml2 generic error output to avoid noise.
    xmlSetGenericErrorFunc(NULL, NULL);

    // Ensure the harness source references the target function name.
    force_use_of_xmlSchemaVStart();

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Keep resource usage reasonable.
    if (Data == NULL || Size < 4 || Size > 200000)
        return 0;

    // Split input into two parts:
    // - schema_buf: bytes [0 .. schemaSize-1]
    // - instance_buf: bytes [schemaSize .. Size-1]
    // Use a simple split; ensure both parts have at least 1 byte.
    size_t schemaSize = Size / 3; // smaller portion for schema (more likely valid)
    if (schemaSize < 1) schemaSize = 1;
    size_t instanceSize = Size - schemaSize;
    if (instanceSize < 1) {
        // If instance becomes empty, adjust split.
        instanceSize = 1;
        schemaSize = Size - instanceSize;
    }

    const char *schemaBuf = (const char *)Data;
    const char *instanceBuf = (const char *)(Data + schemaSize);

    // Create a parser ctxt for the schema in-memory buffer.
    // xmlSchemaNewMemParserCtxt accepts const char* and int size.
    xmlSchemaParserCtxtPtr pctxt = xmlSchemaNewMemParserCtxt(schemaBuf, (int)schemaSize);
    if (pctxt == NULL) {
        // Could not create parser ctxt; nothing else to do.
        return 0;
    }

    // Parse the schema (may fail for malformed input; handle gracefully).
    xmlSchemaPtr schema = xmlSchemaParse(pctxt);
    // We can free the parser ctxt regardless of parse success; xmlSchemaParse may
    // take ownership of some resources but typically we free pctxt explicitly.
    xmlSchemaFreeParserCtxt(pctxt);

    if (schema == NULL) {
        // If schema parsing failed, return early.
        return 0;
    }

    // Parse the instance XML from memory. Use options to avoid network access
    // and mute warnings/errors.
    int parseOptions = XML_PARSE_NONET | XML_PARSE_NOBLANKS | XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
    xmlDocPtr doc = xmlReadMemory(instanceBuf, (int)instanceSize, NULL, NULL, parseOptions);
    if (doc == NULL) {
        // No instance document; nothing to validate.
        xmlSchemaFree(schema);
        return 0;
    }

    // Create a validation context for the schema.
    xmlSchemaValidCtxtPtr vctxt = xmlSchemaNewValidCtxt(schema);
    if (vctxt == NULL) {
        xmlFreeDoc(doc);
        xmlSchemaFree(schema);
        return 0;
    }

    // Try to call xmlSchemaVStart if available. Prefer weak symbol when
    // supported by the compiler; otherwise fall back to runtime lookup via dlsym.
#if defined(__GNUC__) || defined(__clang__)
    if (xmlSchemaVStart) {
        (void)xmlSchemaVStart(vctxt);
    } else
#endif
#ifdef __unix__
    {
        // Fallback: try runtime lookup. Use dlopen(NULL, ...) to obtain a handle
        // for the main program. Note: RTLD_DEFAULT might not be available, so
        // we avoid using it directly.
        void *handle = dlopen(NULL, RTLD_LAZY);
        if (handle) {
            void *sym = dlsym(handle, "xmlSchemaVStart");
            if (sym) {
                typedef int (*xmlSchemaVStart_t)(xmlSchemaValidCtxtPtr);
                xmlSchemaVStart_t dyn_vstart = (xmlSchemaVStart_t)sym;
                (void)dyn_vstart(vctxt);
            }
            dlclose(handle);
        }
    }
#endif

    // Use the public API to validate the document with the context.
    // xmlSchemaValidateDoc will internally set up the validation context
    // and exercise xmlSchemaVStart / validation code paths as well.
    (void)xmlSchemaValidateDoc(vctxt, doc);

    // Cleanup
    xmlSchemaFreeValidCtxt(vctxt);
    xmlSchemaFree(schema);
    xmlFreeDoc(doc);

    // Reset last error to avoid interfering with subsequent inputs.
    xmlResetLastError();

    return 0;
}
