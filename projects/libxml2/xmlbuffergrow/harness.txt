// Generate a fuzz driver based the given function signature in C language. Output the full driver code in reply.
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool 	6 Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool 	6 Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool 	6 Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool 	6 Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool 	6 Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code 	6 View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
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
// // int
// //xmlBufferAdd(xmlBuffer *buf, const xmlChar *str, int len) {
// //    if ((buf == NULL) || (str == NULL))
// //	return(XML_ERR_ARGUMENT);
// //    if (len < 0)
// //        len = xmlStrlen(str);
// //    if (len == 0)
// //        return(XML_ERR_OK);
// //
// //    /* Note that both buf->size and buf->use can be zero here. */
// //    if ((unsigned) len >= buf->size - buf->use) {
// //        if (xmlBufferGrow(buf, len) < 0)
// //            return(XML_ERR_NO_MEMORY);
// //    }
// //
// //    memmove(&buf->content[buf->use], str, len);
// //    buf->use += len;
// //    buf->content[buf->use] = 0;
// //    return(XML_ERR_OK);
// //}
// 
// 
// Useful project headers
// 
// 
// 
// 
// The following function fuzzes
//     int xmlBufferGrow(xmlBuffer * buf, unsigned int len);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
// Fuzz driver for: int xmlBufferGrow(xmlBuffer * buf, unsigned int len);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// This driver constructs an xmlBuffer from fuzz input and calls xmlBufferGrow.
// It takes care to keep allocations bounded to avoid huge allocations during fuzzing.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Use project headers (absolute path as requested) */
#include "/src/libxml2/include/libxml/tree.h"
#include "/src/libxml2/include/libxml/xmlmemory.h"

/* Cap allocations to a reasonable size for fuzzing */
#define MAX_BUFFER_SIZE (64 * 1024) /* 64KB */
#define MAX_LEN_PARAM    (32 * 1024) /* 32KB */

/* Helper to read up to 4 bytes from Data as a 32-bit unsigned value */
static unsigned read_u32_from_bytes(const uint8_t **pdata, size_t *psize) {
    unsigned val = 0;
    for (int i = 0; i < 4; i++) {
        val = (val << 8);
        if (*psize > 0) {
            val |= (unsigned)(*(*pdata));
            (*pdata)++;
            (*psize)--;
        }
    }
    return val;
}

/* Ensure libxml memory function pointers are set to defaults (malloc/realloc/free).
   They are declared in xmlmemory.h as xmlMalloc/xmlRealloc/xmlFree variables.
   Assigning them here keeps behavior predictable in the fuzzing harness. */
static void ensure_xml_memory_hooks(void) {
    /* These symbols are defined in globals.c in libxml2, but may be available
       as externs when linking the project. Assigning them here to defaults. */
    xmlMalloc = malloc;
    xmlRealloc = realloc;
    xmlFree = free;
}

/* Fuzzer entry point */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    ensure_xml_memory_hooks();

    const uint8_t *p = Data;
    size_t remaining = Size;

    /* Build an xmlBuffer instance on the stack and initialize fields. */
    xmlBuffer buf_local;
    xmlBuffer *buf = &buf_local;

    /* Default initialization */
    buf->content = NULL;
    buf->contentIO = NULL;
    buf->use = 0;
    buf->size = 0;
    buf->alloc = XML_BUFFER_ALLOC_DOUBLEIT;

    /* 1) Choose allocation scheme from first byte if available */
    if (remaining >= 1) {
        buf->alloc = (xmlBufferAllocationScheme)((*p) % 5); /* 5 enumerators */
        p++; remaining--;
    }

    /* 2) Read an initial buffer size (cap it) */
    unsigned initial_size = read_u32_from_bytes(&p, &remaining);
    if (initial_size > MAX_BUFFER_SIZE) initial_size = initial_size % (MAX_BUFFER_SIZE + 1);

    /* 3) Read initial 'use' value (must be <= initial_size) */
    unsigned use_val = 0;
    if (initial_size == 0) {
        /* If size is 0, set use to 0 */
        use_val = 0;
    } else {
        unsigned tmp = read_u32_from_bytes(&p, &remaining);
        use_val = tmp % (initial_size + 1U);
    }

    /* 4) Decide whether content and contentIO are the same or different */
    int separate_io = 0;
    if (remaining >= 1) {
        separate_io = (*p) & 1;
        p++; remaining--;
    }

    /* 5) Allocate content and contentIO according to choices, but keep allocations bounded.
       We allocate one extra byte to be able to store a terminating 0 when copying. */
    if (initial_size > 0) {
        /* allocate content */
        buf->content = (xmlChar *)xmlMalloc((size_t)initial_size + 1);
        if (buf->content == NULL) {
            /* Out of memory allocation; abort this input gracefully */
            return 0;
        }
        /* Initialize content with some data from the remaining bytes */
        size_t fill = (size_t)use_val;
        if (fill > 0) {
            /* Fill up to 'fill' bytes or available fuzz bytes */
            size_t tocopy = fill;
            if (tocopy > remaining) tocopy = remaining;
            if (tocopy > 0) {
                memcpy(buf->content, p, tocopy);
                p += tocopy;
                remaining -= tocopy;
            }
            /* If we didn't get enough bytes, pad with zeros */
            if (tocopy < fill) {
                memset(buf->content + tocopy, 0, fill - tocopy);
            }
        }
        /* set a terminating zero */
        buf->content[use_val] = 0;
    } else {
        buf->content = NULL;
    }

    /* NOTE: Avoid allocating a separate contentIO buffer when using IO allocation.
       xmlBufferGrow() can free contentIO internally and then replace both
       buf->content and buf->contentIO with a new allocation. If we allocate two
       independent blocks and xmlBufferGrow() frees contentIO but replaces
       buf->content with the new buffer, the original content buffer would be
       overwritten (lost) and leaked. To prevent leaks, keep contentIO equal to
       content in IO mode. We still allow the fuzz byte 'separate_io' to be
       consumed but ignore it to keep memory consistent. */
    if (buf->alloc == XML_BUFFER_ALLOC_IO) {
        buf->contentIO = buf->content;
    } else {
        /* Non-IO mode: contentIO can be NULL or equal to content; keep it equal for safety */
        buf->contentIO = buf->content;
    }

    buf->size = initial_size;
    buf->use = use_val;

    /* 6) Construct the len parameter to xmlBufferGrow from remaining fuzz bytes */
    unsigned raw_len = 0;
    if (remaining > 0) {
        raw_len = read_u32_from_bytes(&p, &remaining);
    } else {
        /* default small len to attempt growth in some cases */
        raw_len = 1;
    }
    /* Cap len to avoid huge allocations inside xmlBufferGrow */
    unsigned len_param = raw_len;
    if (len_param > MAX_LEN_PARAM) len_param = len_param % (MAX_LEN_PARAM + 1U);

    /* 7) Call the target function under test */
    /* Note: xmlBufferGrow returns int; ignore result. We protect against client code causing
       excessive allocations by capping sizes above. */
    (void)xmlBufferGrow(buf, len_param);

    /* 8) Cleanup allocated memory */
    /* xmlBufferGrow may have reallocated buf->content and buf->contentIO pointers.
       We must free any non-NULL pointer exactly once. */
    if (buf->alloc == XML_BUFFER_ALLOC_IO) {
        /* In IO mode, content and contentIO are the same by construction here. Free once. */
        if (buf->content != NULL) {
            xmlFree(buf->content);
        }
    } else {
        /* Non-IO: only content should be freed (contentIO == content in this harness too) */
        if (buf->content != NULL) {
            xmlFree(buf->content);
        }
    }

    return 0;
}