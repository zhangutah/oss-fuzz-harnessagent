// Fixed fuzz driver for:
//   int xmlSchemaValAtomicListNode(xmlSchemaTypePtr type,
//                                  const xmlChar * value,
//                                  xmlSchemaValPtr * ret,
//                                  xmlNodePtr node);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Notes on the fix:
// - The original harness provided a stub implementation of
//   xmlSchemaValAtomicListNode which caused the fuzzer to exercise a fake
//   function. The real implementation in the project is static inside
//   xmlschemastypes.c so it wasn't available at link time.
// - To ensure the harness exercises the real implementation we include the
//   xmlschemastypes.c source file directly. This brings the static function
//   into this translation unit so it can be called normally.
// - Keep the fuzzer entry point signature unchanged.

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include libxml2 internal headers (paths from repository). Adjust if building
   against an installed libxml2 or a different tree layout. */
#include "/src/libxml2/include/libxml/xmlstring.h"
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/schemasInternals.h"
#include "/src/libxml2/include/libxml/xmlschemastypes.h"

/*
 * Include the implementation so the static xmlSchemaValAtomicListNode defined
 * in xmlschemastypes.c is available to this TU. This ensures we run the
 * project's real code rather than a fake stub.
 *
 * Note: we include the .c file using an absolute path that matches the
 * repository layout used by this build environment.
 */
#include "/src/libxml2/xmlschemastypes.c"

/* The fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Create a NUL-terminated buffer from the fuzzer input */
    size_t buf_len = (Size == 0) ? 1 : (Size + 1);
    xmlChar *value = (xmlChar *)malloc(buf_len);
    if (value == NULL)
        return 0;
    if (Size > 0)
        memcpy(value, Data, Size);
    value[buf_len - 1] = 0; /* NUL-terminate */

    /* Setup simple arguments. Use NULL for complex pointers to exercise
       input parsing paths; also provide a stack xmlSchemaValPtr to observe
       ret-writing behavior if any. */
    xmlSchemaTypePtr type = NULL;
    xmlNodePtr node = NULL;

    /* Provide a place for the function to store a result if it attempts to. */
    xmlSchemaValPtr result = NULL;
    xmlSchemaValPtr *pret = &result;

    /* Call the target function. We ignore the return value; the fuzzer cares
       about crashes, leaks, and undefined behavior. */
    (void)xmlSchemaValAtomicListNode(type, value, pret, node);

    /* Also try passing NULL for the ret pointer to hit alternate paths. */
    (void)xmlSchemaValAtomicListNode(type, value, NULL, node);

    free(value);
    return 0;
}
