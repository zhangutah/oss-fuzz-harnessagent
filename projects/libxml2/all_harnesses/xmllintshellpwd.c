// Fixed fuzz driver that uses the real xmllintShellPwd implementation from the project.
//
// Notes:
// - Instead of providing a local fallback definition, this harness brings in the
//   project's shell.c so the real (project) implementation of xmllintShellPwd is
//   compiled into the fuzzer binary and used at runtime.
// - Keep the LLVMFuzzerTestOneInput signature unchanged.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <libxml/parser.h>
#include <libxml/tree.h>

#ifdef __cplusplus
}
#endif

// Include the project's shell.c so the real (static) xmllintShellPwd implementation
// is available in this translation unit. The fuzz harness resides in
// /src/libxml2/fuzz/regexp.c, and shell.c is at /src/libxml2/shell.c, so use a
// relative include.
#ifdef __cplusplus
extern "C" {
#endif

// Include the implementation file directly so we get the static xmllintShellPwd
// function from the project. This avoids using a fake local definition.
#include "../shell.c"

#ifdef __cplusplus
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    // Initialize parser (no-op if already initialized)
    xmlInitParser();

    // Parse the input bytes as an XML document.
    // Cast Size to int: xmlReadMemory expects an int for size.
    // Use XML_PARSE_NOERROR | XML_PARSE_NOWARNING to reduce noisy output during fuzzing.
    xmlDocPtr doc = xmlReadMemory((const char *)Data, (int)Size, "fuzz.xml", NULL,
                                 XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    if (doc == NULL) {
        xmlCleanupParser();
        return 0;
    }

    // Get the root element (xmlNodePtr)
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        xmlCleanupParser();
        return 0;
    }

    // xmllintShellPwd expects a buffer of at least 500 bytes (per comment in source).
    char buffer[500];
    memset(buffer, 0, sizeof(buffer));

    // Call the target function from the project. The first and last parameters are
    // unused in the implementation, so pass NULL for them.
    if (buffer != NULL && root != NULL) {
        // xmllintShellPwd is brought into this TU by including shell.c above.
        (void)xmllintShellPwd(NULL, buffer, root, NULL);
    }

    // Touch the buffer so the compiler doesn't optimize away the call/result
    volatile unsigned char v = (unsigned char)buffer[0];
    (void)v;

    // Clean up
    xmlFreeDoc(doc);
    xmlCleanupParser();

    return 0;
}
