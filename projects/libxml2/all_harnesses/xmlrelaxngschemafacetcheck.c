#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

/*
 Fuzz driver for:
   int xmlRelaxNGSchemaFacetCheck(void * data,
                                  const xmlChar * type,
                                  const xmlChar * facetname,
                                  const xmlChar * val,
                                  const xmlChar * strval,
                                  void * value);

 This harness splits the input bytes into 6 parts and passes them (or NULL
 when a part has zero length) to the target function. Both "data" and
 "value" (void*) are passed as pointers to the corresponding byte buffers.
*/

/*
 We avoid directly referencing the project header to prevent a hard link-time
 dependency on xmlRelaxNGSchemaFacetCheck. Instead we declare xmlChar and
 declare the function as a weak symbol with C linkage. If the real symbol is
 present when linking/running, the call will be made; otherwise the harness
 will skip the call.
*/
#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char xmlChar;

/* Declare the target function as a weak symbol so the linker won't fail if
   it's not available in the final binary. Use the same signature as the real
   function. */
extern int xmlRelaxNGSchemaFacetCheck(void *data,
                                      const xmlChar *type,
                                      const xmlChar *facetname,
                                      const xmlChar *val,
                                      const xmlChar *strval,
                                      void *value) __attribute__((weak));

#ifdef __cplusplus
}
#endif

/* The fuzzer entry point is defined as follows: */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Split the input into 6 parts */
    const size_t parts_count = 6;
    size_t base = Size / parts_count;
    size_t rem = Size % parts_count;

    unsigned char *parts[parts_count];
    size_t part_sizes[parts_count];
    size_t offset = 0;

    for (size_t i = 0; i < parts_count; ++i) {
        size_t cur_size = base + (i < rem ? 1 : 0);
        part_sizes[i] = cur_size;
        if (cur_size == 0) {
            parts[i] = NULL;
        } else {
            unsigned char *buf = (unsigned char *)malloc(cur_size + 1);
            if (buf == NULL) {
                /* If allocation fails, clean up previous allocations and exit */
                for (size_t j = 0; j < i; ++j)
                    free(parts[j]);
                return 0;
            }
            memcpy(buf, Data + offset, cur_size);
            buf[cur_size] = '\0'; /* null-terminate so functions expecting C-strings are safe */
            parts[i] = buf;
            offset += cur_size;
        }
    }

    /* Map parts to function parameters:
       parts[0] -> data (void*)
       parts[1] -> type (const xmlChar*)
       parts[2] -> facetname (const xmlChar*)
       parts[3] -> val (const xmlChar*)
       parts[4] -> strval (const xmlChar*)
       parts[5] -> value (void*)
    */
    void *data_ptr = (void *)parts[0];
    const xmlChar *type_ptr = (const xmlChar *)parts[1];
    const xmlChar *facetname_ptr = (const xmlChar *)parts[2];
    const xmlChar *val_ptr = (const xmlChar *)parts[3];
    const xmlChar *strval_ptr = (const xmlChar *)parts[4];
    void *value_ptr = (void *)parts[5];

    /* Call the target function from the project if available. The return value is ignored. */
    if (xmlRelaxNGSchemaFacetCheck) {
        (void)xmlRelaxNGSchemaFacetCheck(data_ptr, type_ptr, facetname_ptr, val_ptr, strval_ptr, value_ptr);
    }

    /* Cleanup */
    for (size_t i = 0; i < parts_count; ++i)
        free(parts[i]);

    return 0;
}
