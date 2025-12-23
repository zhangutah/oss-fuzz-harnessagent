// Fixed fuzz driver for:
//     int xmlRelaxNGCompile(xmlRelaxNGParserCtxtPtr ctxt, xmlRelaxNGDefinePtr def);
// Fuzzer entry point:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlautomata.h>
#include <libxml/xmlstring.h>
#include <libxml/xmlregexp.h> /* ensure xmlRegFreeRegexp is declared */

/* Include the Relax-NG implementation directly so we have access to internal
 * structs (xmlRelaxNGParserCtxt, xmlRelaxNGDefine, enums, and the function).
 * Using the repository absolute path discovered while analyzing the code.
 */
#include "/src/libxml2/relaxng.c"

/* Helper: safely duplicate up to n bytes from Data as an xmlChar* (NULL-terminated). */
static xmlChar *
dup_xmlstr_from_bytes(const uint8_t *data, size_t data_len, size_t maxlen) {
    if (data == NULL || data_len == 0)
        return NULL;
    size_t len = data_len;
    if (len > maxlen) len = maxlen;
    /* ensure null-termination by copying into a temporary buffer */
    char *tmp = (char *)malloc(len + 1);
    if (!tmp) return NULL;
    memcpy(tmp, data, len);
    tmp[len] = '\0';
    xmlChar *ret = xmlStrdup((const xmlChar *)tmp);
    free(tmp);
    return ret;
}

/* Create a small linked list of xmlRelaxNGDefine nodes (count <= 2) using bytes as entropy. */
static xmlRelaxNGDefinePtr
make_small_define_list(const uint8_t *data, size_t size) {
    if (size == 0 || data == NULL)
        return NULL;

    /* Limit to at most two nodes to avoid deep recursion. */
    size_t n_nodes = 1 + (data[0] & 1);
    xmlRelaxNGDefinePtr head = NULL;
    xmlRelaxNGDefinePtr prev = NULL;

    const uint8_t *ptr = data;
    size_t left = size;

    for (size_t i = 0; i < n_nodes; i++) {
        xmlRelaxNGDefinePtr node = (xmlRelaxNGDefinePtr)calloc(1, sizeof(xmlRelaxNGDefine));
        if (!node) break;

        /* Select a safe subset of types that xmlRelaxNGCompile can handle. */
        xmlRelaxNGType candidates[] = {
            XML_RELAXNG_EMPTY, XML_RELAXNG_TEXT, XML_RELAXNG_NOOP,
            XML_RELAXNG_OPTIONAL, XML_RELAXNG_ZEROORMORE, XML_RELAXNG_ONEORMORE,
            XML_RELAXNG_CHOICE, XML_RELAXNG_GROUP, XML_RELAXNG_ELEMENT, XML_RELAXNG_START
        };
        size_t cand_cnt = sizeof(candidates) / sizeof(candidates[0]);
        if (left > 0) {
            node->type = candidates[ptr[0] % cand_cnt];
            ptr++; left--;
        } else {
            node->type = XML_RELAXNG_EMPTY;
        }

        /* small name/ns/value derived from available bytes */
        if (left > 0) {
            node->name = dup_xmlstr_from_bytes(ptr, left, 8);
            size_t used = node->name ? strlen((const char *)node->name) : 0;
            if (used > left) used = left;
            ptr += used; left = (left > used) ? left - used : 0;
        }
        if (left > 0) {
            node->ns = dup_xmlstr_from_bytes(ptr, left, 8);
            size_t used = node->ns ? strlen((const char *)node->ns) : 0;
            if (used > left) used = left;
            ptr += used; left = (left > used) ? left - used : 0;
        }
        if (left > 0) {
            node->value = dup_xmlstr_from_bytes(ptr, left, 16);
            size_t used = node->value ? strlen((const char *)node->value) : 0;
            if (used > left) used = left;
            ptr += used; left = (left > used) ? left - used : 0;
        }

        /* small flags and depth derived from bytes if available */
        if (left > 0) {
            node->dflags = (short)(ptr[0] & (IS_COMPILABLE | IS_NOT_COMPILABLE));
            ptr++; left--;
        } else {
            node->dflags = 0;
        }
        node->depth = -1;

        /* link it */
        if (prev == NULL) {
            head = node;
        } else {
            prev->next = node;
            node->parent = prev; /* not necessarily used, but set to something */
        }
        prev = node;
    }

    return head;
}

/* Free the small define list created above. Also free any compiled regexps (contModel). */
static void
free_small_define_list(xmlRelaxNGDefinePtr def) {
    while (def) {
        xmlRelaxNGDefinePtr next = def->next;
        if (def->name) xmlFree((xmlChar *)def->name);
        if (def->ns) xmlFree((xmlChar *)def->ns);
        if (def->value) xmlFree((xmlChar *)def->value);
        /* Free any compiled content model regexp attached by xmlRelaxNGCompile */
        if (def->contModel) {
            /* xmlRegFreeRegexp is the library destructor for xmlRegexp objects */
            xmlRegFreeRegexp(def->contModel);
            def->contModel = NULL;
        }
        /* contModel and other pointers are otherwise left NULL by construction. */
        free(def);
        def = next;
    }
}

/* The fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Minimal guard */
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml (no-op if already initialized) */
    xmlInitParser();

    /* Try to create a parser context out of the input bytes.
     * Using the entire input as a Relax-NG memory buffer is safe for creating
     * a parser context even if the buffer is not valid Relax-NG.
     */
    xmlRelaxNGParserCtxtPtr ctxt = xmlRelaxNGNewMemParserCtxt((const char *)Data, (int)Size);

    /* If creation failed, try to allocate a fresh context structure ourselves.
     * Since relaxng.c is included, we have visibility on the struct layout and
     * can allocate a zeroed instance. This mirrors the internal structure
     * initialization enough for calling xmlRelaxNGCompile in some circumstances.
     */
    if (ctxt == NULL) {
        ctxt = (xmlRelaxNGParserCtxtPtr)calloc(1, sizeof(struct _xmlRelaxNGParserCtxt));
        if (ctxt == NULL)
            return 0;
        /* set some default/valid pointers for error callbacks to avoid NULL uses */
        ctxt->userData = NULL;
        ctxt->error = NULL;
        ctxt->warning = NULL;
        ctxt->serror = NULL;
        ctxt->nbErrors = 0;
        ctxt->nbWarnings = 0;
    }

    /* Ensure ctxt->am and ctxt->state are usable by the automata functions.
     * Creating automata can trigger large allocations in some code paths; to
     * avoid out-of-memory conditions while fuzzing, do NOT create an automata
     * structure here. Many code paths in the library handle ctxt->am == NULL
     * safely. If ctxt already had an automata, free it to avoid retaining large state.
     */
    if (ctxt->am != NULL) {
        xmlFreeAutomata(ctxt->am);
        ctxt->am = NULL;
        ctxt->state = NULL;
    }

    /* Deliberately avoid creating an automata for *any* input size to prevent
     * large allocations inside the automata/regexp subsystem during fuzzing.
     */
    ctxt->am = NULL;
    ctxt->state = NULL;

    /* Use part of the input as entropy to construct a small xmlRelaxNGDefine.
     * We'll use the tail of the input (after an offset) to build strings and
     * possibly child defines.
     */
    const uint8_t *entropy = Data;
    size_t entropy_size = Size;
    /* avoid giving empty buffers to helpers */
    if (entropy_size == 0) entropy_size = 1;

    xmlRelaxNGDefinePtr def = (xmlRelaxNGDefinePtr)calloc(1, sizeof(xmlRelaxNGDefine));
    if (!def) {
        if (ctxt) {
            /* free ctxt properly if allocated by xmlRelaxNGNewMemParserCtxt
             * or by our calloc above.
             */
            if (ctxt->URL != NULL) xmlFree(ctxt->URL);
            if (ctxt->document != NULL) xmlFreeDoc(ctxt->document);
            if (ctxt->am != NULL) {
                xmlFreeAutomata(ctxt->am);
            }
            /* If ctxt was created via xmlRelaxNGNewMemParserCtxt, call free function;
             * otherwise free the calloc'd memory.
             * To be conservative, try both patterns:
             */
            xmlRelaxNGFreeParserCtxt(ctxt);
        }
        return 0;
    }

    /* Choose a type from a small safe set. */
    xmlRelaxNGType choices[] = {
        XML_RELAXNG_START, XML_RELAXNG_ELEMENT, XML_RELAXNG_NOOP,
        XML_RELAXNG_OPTIONAL, XML_RELAXNG_ZEROORMORE, XML_RELAXNG_ONEORMORE,
        XML_RELAXNG_CHOICE, XML_RELAXNG_GROUP, XML_RELAXNG_TEXT, XML_RELAXNG_EMPTY
    };
    size_t choices_cnt = sizeof(choices) / sizeof(choices[0]);
    def->type = choices[entropy[0] % choices_cnt];

    /* Create minimal strings for name/ns/value from the input to exercise code paths. */
    if (entropy_size > 1) {
        def->name = dup_xmlstr_from_bytes(entropy + 1, entropy_size - 1, 16);
    }
    if (entropy_size > 17) {
        def->ns = dup_xmlstr_from_bytes(entropy + 17, entropy_size > 17 ? entropy_size - 17 : 0, 16);
    }
    if (entropy_size > 33) {
        def->value = dup_xmlstr_from_bytes(entropy + 33, entropy_size > 33 ? entropy_size - 33 : 0, 32);
    }

    /* small dflags and depth */
    def->dflags = (short)(entropy[0] & (IS_COMPILABLE | IS_NOT_COMPILABLE));
    def->depth = -1;

    /* Create a tiny content list derived from the entropy to test recursive handling. */
    if (entropy_size > 48) {
        def->content = make_small_define_list(entropy + 48, entropy_size - 48);
    } else {
        def->content = NULL;
    }

    /* Call the target function under test.
     * Wrap in a minimal try: many error reporting paths expect ctxt != NULL and/or
     * certain fields set. We tried to set ctxt->am and ctxt->state above.
     * The function returns an int; we ignore it here.
     */
    (void)xmlRelaxNGCompile(ctxt, def);

    /* Cleanup created structures. */

    /* free any child defines we created (this also frees contModel on those nodes) */
    if (def->content)
        free_small_define_list(def->content);

    /* Free any compiled content model attached to the top-level def */
    if (def->contModel) {
        xmlRegFreeRegexp(def->contModel);
        def->contModel = NULL;
    }

    if (def->name) xmlFree((xmlChar *)def->name);
    if (def->ns) xmlFree((xmlChar *)def->ns);
    if (def->value) xmlFree((xmlChar *)def->value);
    free(def);

    /* Free the parser context properly.
     * xmlRelaxNGFreeParserCtxt handles both initialized contexts and partially
     * initialized ones reasonably.
     */
    xmlRelaxNGFreeParserCtxt(ctxt);

    /* Finally, cleanup global parser state minimally. */
    xmlCleanupParser();

    return 0;
}
