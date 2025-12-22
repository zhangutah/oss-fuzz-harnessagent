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
//     int xmlValidGetValidElements(xmlNode * prev, xmlNode * next, const xmlChar ** names, int max);
// 
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
// int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// 
// Output the Full driver code in reply.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Use the project header for the validation function */
#include "/src/libxml2/include/libxml/valid.h"
#include <libxml/parser.h> /* for xmlNewDoc, xmlNewChild, xmlFreeDoc */
#include <libxml/tree.h>   /* for xmlNodePtr */

/*
 * Fuzzer entry point for libFuzzer:
 *   int xmlValidGetValidElements(xmlNode * prev, xmlNode * next,
 *                                const xmlChar ** names, int max);
 *
 * This driver builds a tiny xmlDoc with two sibling nodes (prev and next),
 * builds a names array from the input bytes, and calls
 * xmlValidGetValidElements with those values.
 *
 * It tries to avoid crashing by doing basic bounds checks and freeing
 * allocated memory.
 */

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0)
        return 0;

    /* Initialize libxml parser (safe to call multiple times) */
    xmlInitParser();

    /* Create a minimal document with a root and two child nodes */
    xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
    if (doc == NULL)
        return 0;

    xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "root");
    if (root == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }
    xmlDocSetRootElement(doc, root);

    /* Create two sibling child nodes to serve as prev and next */
    xmlNodePtr child1 = xmlNewChild(root, NULL, BAD_CAST "child1", NULL);
    xmlNodePtr child2 = xmlNewChild(root, NULL, BAD_CAST "child2", NULL);
    if (child1 == NULL || child2 == NULL) {
        xmlFreeDoc(doc);
        return 0;
    }

    /* Prepare to parse Data into a names array:
       - First byte (if present) determines the number of names (0..16)
       - Remaining bytes are consumed to form null-terminated strings
    */
    size_t offset = 0;
    unsigned int names_count = (unsigned int)(Data[0] % 17); /* 0..16 */
    offset = 1;

    const xmlChar **names = NULL;
    if (names_count > 0) {
        names = (const xmlChar **)malloc(sizeof(const xmlChar *) * names_count);
        if (!names) {
            xmlFreeDoc(doc);
            return 0;
        }
        memset((void *)names, 0, sizeof(const xmlChar *) * names_count);

        for (unsigned int i = 0; i < names_count; ++i) {
            if (offset >= Size) {
                /* No bytes left: use an empty string */
                xmlChar *s = (xmlChar *)malloc(1);
                if (s) s[0] = '\0';
                names[i] = (const xmlChar *)s;
                continue;
            }

            /* Determine length for this name: use next byte as length (0..remaining) */
            size_t max_rem = Size - offset;
            size_t len = Data[offset] % (max_rem + 1); /* allows len==max_rem */
            offset += 1;

            /* Bound len to something reasonable to avoid huge allocations */
            if (len > 1024) len = 1024;

            /* If not enough bytes left to fill len, clamp it */
            if (len > Size - offset)
                len = Size - offset;

            xmlChar *s = (xmlChar *)malloc(len + 1);
            if (!s) {
                /* On allocation failure, free what we have and exit gracefully */
                for (unsigned int j = 0; j < i; ++j)
                    free((void *)names[j]);
                free(names);
                xmlFreeDoc(doc);
                return 0;
            }

            if (len > 0)
                memcpy(s, Data + offset, len);
            s[len] = '\0';
            names[i] = (const xmlChar *)s;

            offset += len;
        }
    }

    /* Determine max parameter from remaining bytes (or from names_count) */
    int max = names_count;
    if (offset < Size) {
        /* Use next byte to vary max; allow negative and larger numbers to stress code */
        int pick = (int)Data[offset];
        max = (pick % 40) - 10; /* range approx -10 .. 29 */
        offset += 1;
    }

    /* Call the target function with prev = child1, next = child2 */
    /* The API expects xmlChar** typed as const xmlChar ** */
    /* Cast names to const xmlChar** is already that type */
    /* If names_count == 0, pass NULL */
    const xmlChar **names_arg = (names_count > 0) ? names : NULL;

    /* Protect call with a simple try: function is in-process, so just call it */
    /* The return value is ignored for fuzzing purposes */
    (void)xmlValidGetValidElements(child1, child2, names_arg, max);

    /* Cleanup allocated names */
    if (names) {
        for (unsigned int i = 0; i < names_count; ++i) {
            if (names[i])
                free((void *)names[i]);
        }
        free(names);
    }

    /* Free the document (also frees nodes) */
    xmlFreeDoc(doc);

    /* Optional: cleanup parser globals (can be expensive) */
    /* xmlCleanupParser(); /* commented out to avoid races in multi-threaded fuzzers */

    return 0;
}
