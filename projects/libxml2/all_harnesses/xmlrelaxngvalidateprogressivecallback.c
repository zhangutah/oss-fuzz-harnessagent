// Fixed fuzz driver for:
//   void xmlRelaxNGValidateProgressiveCallback(xmlRegExecCtxtPtr exec,
//                                              const xmlChar * token,
//                                              void * transdata,
//                                              void * inputdata);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This harness includes the project's relaxng.c so the static
// xmlRelaxNGValidateProgressiveCallback implementation from the project
// is available in this translation unit and will be used by the fuzzer.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/xmlstring.h>
#include <libxml/xmlregexp.h>
#include <libxml/tree.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Include the real implementation from the project so the static
 * function xmlRelaxNGValidateProgressiveCallback is available here.
 * The path is relative to this fuzz harness source file.
 */
#include "../relaxng.c"

#ifdef __cplusplus
} // extern "C"
#endif

/*
 * LLVMFuzzerTestOneInput
 *
 * Uses the provided input to:
 *  - set the token (xmlChar*)
 *  - attempt to compile the token as a regexp and attach it to define->contModel
 *  - provide a non-NULL transdata (xmlRelaxNGDefine) and a minimal
 *    xmlRelaxNGValidCtxt with a valid xmlNode (XML_ELEMENT_NODE)
 *
 * This ensures the fuzz data affects the execution paths inside
 * xmlRelaxNGValidateProgressiveCallback.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Limit allocation size to avoid excessive allocations in the harness.
    const size_t max_alloc = 1 << 20; // 1MB
    size_t buf_size = Size;
    if (buf_size > max_alloc) buf_size = max_alloc;

    // Ensure at least 1 byte available so we can NUL-terminate.
    if (buf_size == 0) buf_size = 1;

    // Allocate buffer with room for NUL terminator.
    char *buf = (char*)malloc(buf_size + 1);
    if (!buf) return 0;

    // Copy as much as we can from Data, and NUL-terminate.
    if (Size >= buf_size)
        memcpy(buf, Data, buf_size);
    else if (Size > 0)
        memcpy(buf, Data, Size);
    // Ensure NUL-termination.
    buf[buf_size] = '\0';

    // Cast to xmlChar* (libxml2 uses xmlChar as unsigned char).
    const xmlChar *token = (const xmlChar *)buf;

    // Allocate a minimal xmlRelaxNGValidCtxt so the library won't abort on NULL.
    struct _xmlRelaxNGValidCtxt *ctxt =
        (struct _xmlRelaxNGValidCtxt *)calloc(1, sizeof(struct _xmlRelaxNGValidCtxt));
    if (!ctxt) {
        free(buf);
        return 0;
    }

    // Provide a minimal xmlNode (element) so code accessing node fields won't crash.
    xmlNodePtr node = (xmlNodePtr)calloc(1, sizeof(xmlNode));
    if (!node) {
        // use the library cleanup to free any internal allocations (none yet, but safe)
        xmlRelaxNGFreeValidCtxt(ctxt);
        free(buf);
        return 0;
    }
    node->type = XML_ELEMENT_NODE;
    // Assign the node name to the token so the fuzz input affects element name handling too.
    node->name = (xmlChar *)buf;
    node->ns = NULL; // no namespace
    ctxt->pnode = node;

    // Create a minimal define structure and set it to element type so callback proceeds.
    struct _xmlRelaxNGDefine *define =
        (struct _xmlRelaxNGDefine *)calloc(1, sizeof(struct _xmlRelaxNGDefine));
    if (!define) {
        free(node);
        xmlRelaxNGFreeValidCtxt(ctxt);
        free(buf);
        return 0;
    }
    define->type = XML_RELAXNG_ELEMENT;
    define->attrs = NULL;
    define->name = NULL;
    define->ns = NULL;
    define->contModel = NULL;

    // Try to compile the token as a regexp. If compilation succeeds, the
    // callback will exercise the branch that creates an exec ctxt.
    xmlRegexp *compiled = NULL;
    if (token != NULL) {
        // xmlRegexpCompile expects xmlChar*, compile may fail and return NULL.
        compiled = xmlRegexpCompile(token);
        define->contModel = (xmlRegexpPtr)compiled;
    }

    // Call the real project function with non-NULL transdata (define)
    // and a valid minimal context (ctxt). exec is passed as NULL as in harness.
    xmlRelaxNGValidateProgressiveCallback(NULL, token, (void *)define, (void *)ctxt);

    // Free compiled regexp if created.
    if (compiled != NULL) {
        xmlRegFreeRegexp(compiled);
    }

    // Free allocated structures. Use the library-provided cleanup for ctxt.
    free(define);
    free(node);
    xmlRelaxNGFreeValidCtxt(ctxt);
    free(buf);
    return 0;
}
