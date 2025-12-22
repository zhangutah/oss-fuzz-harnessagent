#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/*
 * Include the implementation so we can call the static function
 * xmlRelaxNGValidateDatatype directly from this translation unit.
 */
#include "/src/libxml2/relaxng.c"

/*
 * A small free function used by the fake type library to free result objects.
 */
static void
fuzz_free(void *data ATTRIBUTE_UNUSED, void *result) {
    if (result != NULL)
        free(result);
}

/*
 * The checking function used by the fake type library.
 *
 * Behavior:
 *  - If value == NULL: return -1 (error).
 *  - Otherwise inspect value[0] (first byte) and choose return codes:
 *      byte % 6 == 0 -> return -1
 *      byte % 6 == 1 -> if result pointer provided, allocate small result; return 1 (success)
 *      byte % 6 == 2 -> if result pointer provided, allocate small result; return 2 (duplicate id)
 *      byte % 6 == 3 -> return 3 (unexpected code -> leads to error path)
 *      byte % 6 == 4 -> return 0 (leading to error path in caller)
 *      else           -> return 1 (success)
 *
 * This ensures the fuzzer data affects control flow inside xmlRelaxNGValidateDatatype
 * (different return values produce different branches).
 */
static int
fuzz_type_check(void *data ATTRIBUTE_UNUSED,
                const xmlChar *type ATTRIBUTE_UNUSED,
                const xmlChar *value,
                void **result,
                xmlNode *node ATTRIBUTE_UNUSED) {
    (void) data;
    (void) type;
    (void) node;

    if (value == NULL) {
        return -1;
    }

    unsigned char b = (unsigned char)value[0];
    switch (b % 6) {
    case 0:
        return -1;
    case 1:
        if (result != NULL) {
            void *r = malloc(16);
            if (r) {
                memset(r, 0x41, 16);
                *result = r;
            }
        }
        return 1;
    case 2:
        if (result != NULL) {
            void *r = malloc(24);
            if (r) {
                memset(r, 0x42, 24);
                *result = r;
            }
        }
        return 2;
    case 3:
        return 3;
    case 4:
        return 0;
    default:
        if (result != NULL) {
            void *r = malloc(8);
            if (r) {
                memset(r, 0x43, 8);
                *result = r;
            }
        }
        return 1;
    }
}

/*
 * Fuzzer entry point.
 *
 * Build minimal structures required by xmlRelaxNGValidateDatatype:
 * - a zeroed xmlRelaxNGValidCtxt structure
 * - a xmlRelaxNGTypeLibrary that uses fuzz_type_check and fuzz_free
 * - an xmlRelaxNGDefine whose attrs contains a param-type define so the
 *   library will be called with &result
 *
 * The fuzz input bytes are copied into a NUL-terminated buffer and passed
 * as the 'value' parameter.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Copy the fuzz input into a NUL-terminated xmlChar buffer */
    xmlChar *value = (xmlChar *)malloc(Size + 1);
    if (value == NULL)
        return 0;
    memcpy(value, Data, Size);
    value[Size] = 0;

    /* Allocate and zero a validation context. */
    xmlRelaxNGValidCtxtPtr vctxt = (xmlRelaxNGValidCtxtPtr)calloc(1, sizeof(xmlRelaxNGValidCtxt));
    if (vctxt == NULL) {
        free(value);
        return 0;
    }

    /* Prepare a fake type library */
    xmlRelaxNGTypeLibrary *lib = (xmlRelaxNGTypeLibrary *)calloc(1, sizeof(xmlRelaxNGTypeLibrary));
    if (lib == NULL) {
        free(vctxt);
        free(value);
        return 0;
    }
    lib->namespace = NULL;
    lib->data = NULL;
    lib->have = NULL;
    lib->check = fuzz_type_check;
    lib->comp = NULL;
    lib->facet = NULL;
    lib->freef = fuzz_free;

    /* Prepare a define structure pointing to our fake library */
    xmlRelaxNGDefinePtr define = (xmlRelaxNGDefinePtr)calloc(1, sizeof(xmlRelaxNGDefine));
    if (define == NULL) {
        free(lib);
        free(vctxt);
        free(value);
        return 0;
    }
    define->data = (void *)lib;
    define->name = (xmlChar *)xmlStrdup(BAD_CAST "fuzzType");
    define->attrs = NULL;
    define->content = NULL;
    define->node = NULL;

    /* Create an attrs entry of type XML_RELAXNG_PARAM so the library is called
     * with &result (the branch that uses result will be exercised).
     */
    xmlRelaxNGDefinePtr param = (xmlRelaxNGDefinePtr)calloc(1, sizeof(xmlRelaxNGDefine));
    if (param != NULL) {
        param->type = XML_RELAXNG_PARAM;
        param->name = (xmlChar *)xmlStrdup(BAD_CAST "fuzzParam");
        param->value = NULL;
        param->next = NULL;
        define->attrs = param;
    } else {
        /* If allocation failed, proceed without attrs (still okay) */
        define->attrs = NULL;
    }

    /* Call the target function. node = NULL is fine for our check function. */
    (void)xmlRelaxNGValidateDatatype(vctxt, value, define, NULL);

    /* Cleanup */
    if (define->name) xmlFree(define->name);
    if (define->attrs) {
        if (define->attrs->name) xmlFree(define->attrs->name);
        free(define->attrs);
    }
    free(define);
    free(lib);
    free(vctxt);
    free(value);

    return 0;
}