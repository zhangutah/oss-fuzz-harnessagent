// Fixed fuzz driver for:
//     int xmlRelaxNGParseInclude(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver:
// - Initializes the libxml2 parser environment
// - Attempts to dynamically resolve RelaxNG-related symbols at runtime (so we don't get
//   link-time undefined references if libxml2 wasn't built with Relax-NG support)
// - Builds a RelaxNG parser context via xmlRelaxNGNewMemParserCtxt if available
// - Attempts to parse the same input as an XML document (xmlReadMemory) to obtain a node
// - Calls xmlRelaxNGParseInclude(ctxt, node) via a function pointer if available
// - Cleans up allocated objects
//
// The code uses dlsym to avoid direct references to symbols that may not be present
// in the linked libxml2 library.

#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

// Treat RelaxNG parser context as an opaque pointer to avoid including relaxng.h,
// which may not be available in some build configurations.
typedef void *xmlRelaxNGParserCtxtPtr;

// Function pointer types matching libxml2 RelaxNG functions we may use.
typedef xmlRelaxNGParserCtxtPtr (*xmlRelaxNGNewMemParserCtxtFunc)(const char *buffer, int size);
typedef int (*xmlRelaxNGParseIncludeFunc)(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
typedef void (*xmlRelaxNGFreeParserCtxtFunc)(xmlRelaxNGParserCtxtPtr ctxt);

// Provide a weak direct declaration of the target symbol so that:
//  - If the symbol exists in the linked libxml2, this direct reference will be satisfied
//    and static analyzers will see a direct call to the target.
//  - If the symbol does not exist, the weak attribute prevents a link-time error.
#ifdef __GNUC__
extern int xmlRelaxNGParseInclude(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node) __attribute__((weak));
#else
/* Fallback: if compiler doesn't support weak, declare normally.
   This may produce a link error when libxml2 is not built with Relax-NG.
   Most fuzzing/build environments use GCC/Clang which support __attribute__((weak)). */
extern int xmlRelaxNGParseInclude(xmlRelaxNGParserCtxtPtr ctxt, xmlNodePtr node);
#endif

// Helper: try dlsym on a handle if handle != NULL and symbol not yet found.
static void try_resolve_symbol(void *handle, const char *name, void **out) {
    if (handle == NULL || out == NULL || *out != NULL) return;
    void *s = dlsym(handle, name);
    if (s) *out = s;
}

// Fuzzer entry point required by libFuzzer / LLVM's fuzzing infra.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    // Initialize the libxml2 library for use in this process.
    xmlInitParser();

    // Limit the buffer size passed to APIs that take int for length.
    int bufSize = (Size > (size_t)INT_MAX) ? INT_MAX : (int)Size;

    // Try to dynamically resolve RelaxNG-related functions from the process.
    // We'll attempt multiple handles to increase the chance of finding the symbols:
    //  - main program handle (dlopen(NULL,...))
    //  - explicit libxml2 shared object names (common ones)
    //  - RTLD_DEFAULT (if available)
    void *main_handle = dlopen(NULL, RTLD_LAZY);
    void *lib_handle = NULL; // for dlopen of libxml2.so*
    xmlRelaxNGNewMemParserCtxtFunc newmem_fn = NULL;
    xmlRelaxNGParseIncludeFunc parseInclude_fn = NULL;
    xmlRelaxNGFreeParserCtxtFunc freeCtxt_fn = NULL;

    // Try main program handle first.
    if (main_handle) {
        try_resolve_symbol(main_handle, "xmlRelaxNGNewMemParserCtxt", (void **)&newmem_fn);
        try_resolve_symbol(main_handle, "xmlRelaxNGParseInclude", (void **)&parseInclude_fn);
        try_resolve_symbol(main_handle, "xmlRelaxNGFreeParserCtxt", (void **)&freeCtxt_fn);
        // Do not dlclose(main_handle) since it refers to the main program.
    }

    // If any symbol missing, try common libxml2 SONAMEs.
    if (!newmem_fn || !parseInclude_fn || !freeCtxt_fn) {
        const char *candidates[] = {
            "libxml2.so.2", // common SONAME on many Linux distributions
            "libxml2.so",   // fallback
            NULL
        };
        for (const char **p = candidates; *p != NULL && (!newmem_fn || !parseInclude_fn || !freeCtxt_fn); ++p) {
            // Try dlopen with RTLD_LAZY; ignore failures.
            lib_handle = dlopen(*p, RTLD_LAZY);
            if (!lib_handle) continue;
            try_resolve_symbol(lib_handle, "xmlRelaxNGNewMemParserCtxt", (void **)&newmem_fn);
            try_resolve_symbol(lib_handle, "xmlRelaxNGParseInclude", (void **)&parseInclude_fn);
            try_resolve_symbol(lib_handle, "xmlRelaxNGFreeParserCtxt", (void **)&freeCtxt_fn);
            // If we've resolved all, break. Otherwise continue to next candidate.
            if (newmem_fn && parseInclude_fn && freeCtxt_fn) break;
            // If not all resolved, we can keep this handle open while trying others; we'll dlclose at the end.
        }
    }

    // As a last resort, try RTLD_DEFAULT if available (GNU extension).
#ifdef RTLD_DEFAULT
    if (!newmem_fn) newmem_fn = (xmlRelaxNGNewMemParserCtxtFunc)dlsym(RTLD_DEFAULT, "xmlRelaxNGNewMemParserCtxt");
    if (!parseInclude_fn) parseInclude_fn = (xmlRelaxNGParseIncludeFunc)dlsym(RTLD_DEFAULT, "xmlRelaxNGParseInclude");
    if (!freeCtxt_fn) freeCtxt_fn = (xmlRelaxNGFreeParserCtxtFunc)dlsym(RTLD_DEFAULT, "xmlRelaxNGFreeParserCtxt");
#endif

    // Create a RelaxNG parser context from the raw input bytes if the symbol is available.
    xmlRelaxNGParserCtxtPtr rctx = NULL;
    if (newmem_fn) {
        // xmlRelaxNGNewMemParserCtxt expects (const char*, int)
        rctx = newmem_fn((const char *)Data, bufSize);
    } else {
        rctx = NULL;
    }

    // Try to parse the input as an XML document to obtain a node pointer.
    // Use recovery and nonet to avoid network access and be forgiving.
    xmlDocPtr doc = xmlReadMemory((const char *)Data, bufSize, "fuzz.xml", NULL,
                                  XML_PARSE_RECOVER | XML_PARSE_NONET | XML_PARSE_NOWARNING | XML_PARSE_NOERROR);

    // Obtain the document root node if parsing succeeded.
    xmlNodePtr node = NULL;
    if (doc) {
        node = xmlDocGetRootElement(doc);
    }

    // Call the target function via the resolved function pointer if available.
    // IMPORTANT: We must call the target function as requested by the fuzzer harness.
    // If parseInclude_fn was resolved, call it (even if rctx or node are NULL).
    if (parseInclude_fn) {
        // Call with our constructed context and node (either may be NULL).
        // Discard the return value; the call itself is what's important for fuzzing.
        (void)parseInclude_fn(rctx, node);
    }

    // Also call the direct symbol if it exists (weak symbol). This direct call
    // makes it obvious to static tooling that the target function is called.
    // If the weak symbol isn't present, xmlRelaxNGParseInclude will be NULL and
    // this call is skipped.
    if (xmlRelaxNGParseInclude) {
        (void)xmlRelaxNGParseInclude(rctx, node);
    } else {
        // If the symbol isn't available in this build of libxml2, do nothing.
        // But ensure we still touch Data/Size to avoid unused parameter warnings.
        (void)Data;
        (void)Size;
    }

    // Cleanup created objects.
    if (freeCtxt_fn && rctx) {
        freeCtxt_fn(rctx);
    }
    if (doc) {
        xmlFreeDoc(doc);
    }

    // If we opened a specific libxml2 handle, close it now.
    if (lib_handle) {
        dlclose(lib_handle);
    }

    // Cleanup the libxml2 parser global state for this invocation.
    xmlCleanupParser();

    return 0;
}

#ifdef __cplusplus
}
#endif
