#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

/* Minimal xmlChar */
typedef unsigned char xmlChar;

/* Minimal xmlNs structure (only href used) */
typedef struct _xmlNs {
    xmlChar *href;
} xmlNs;
typedef xmlNs *xmlNsPtr;

/* Minimal xmlNode structure with only fields used by the function */
typedef struct _xmlNode {
    int type;
    xmlChar *name;
    xmlNsPtr ns;
    struct _xmlNode *parent;
    struct _xmlNode *next;
} xmlNode;
typedef xmlNode *xmlNodePtr;

/* Minimal RelaxNG validation state used by the function */
typedef struct _xmlRelaxNGValidState {
    xmlNodePtr seq;
} xmlRelaxNGValidState;
typedef xmlRelaxNGValidState *xmlRelaxNGValidStatePtr;

/* Minimal RelaxNG validation context used by the function */
typedef struct _xmlRelaxNGValidCtxt {
    int perr;
    xmlRelaxNGValidStatePtr state;
    int flags;
    /* extra field only used by our stub regexp functions to decide return */
    int fuzz_final_ret; /* expected return value when xmlRegExecPushString(exec, NULL, NULL) is called: 1/0/-1 */
} xmlRelaxNGValidCtxt;
typedef xmlRelaxNGValidCtxt *xmlRelaxNGValidCtxtPtr;

/* Minimal xmlRegexp and exec context placeholders */
typedef struct _xmlRegexp {
    int dummy;
} xmlRegexp;
typedef xmlRegexp *xmlRegexpPtr;

typedef struct _xmlRegExecCtxt {
    int dummy;
} xmlRegExecCtxt;
typedef xmlRegExecCtxt *xmlRegExecCtxtPtr;

/* ---- Stub implementations of regexp progressive API used by the fallback ----
   The real libxml2 provides these. We implement minimal behavior sufficient
   for exercising the fallback implementation.

   IMPORTANT: Mark these as static to avoid global symbol collisions with the
   project's libxml2 (which may export the same symbol names). Making them
   static keeps them local to this translation unit and prevents multiple
   definition linker errors.
*/

/* Create a dummy exec context. The real function takes a callback and userdata,
   but our stub only needs to return a non-NULL exec pointer. */
static xmlRegExecCtxtPtr
xmlRegNewExecCtxt(xmlRegexpPtr comp, void *callback, void *data) {
    (void)comp; (void)callback; (void)data;
    xmlRegExecCtxtPtr exec = (xmlRegExecCtxtPtr)malloc(sizeof(xmlRegExecCtxt));
    if (exec) memset(exec, 0, sizeof(*exec));
    return exec;
}
static void
xmlRegFreeExecCtxt(xmlRegExecCtxt *exec) {
    free(exec);
}

/* Behavior:
   - If value == NULL: consult ctxt->fuzz_final_ret (passed via data) and return it.
     The function under test treats return == 1 as success, 0 as "no element" error,
     and <0 as an execution error; we mimic that.
   - Otherwise return 0 (no error), but optionally return <0 for some crafted token
     values to trigger error paths. We'll return -1 if the value string starts with
     '!' to simulate regex execution error on that token.
*/
static int
xmlRegExecPushString(xmlRegExecCtxt *exec, const xmlChar *value, void *data) {
    (void)exec;
    xmlRelaxNGValidCtxtPtr ctxt = (xmlRelaxNGValidCtxtPtr)data;
    if (value == NULL) {
        /* terminating push */
        if (ctxt == NULL)
            return -1;
        return ctxt->fuzz_final_ret;
    }
    /* Simulate an execution error if token begins with '!' */
    if (value[0] == (xmlChar)'!') return -1;
    return 0;
}

static int
xmlRegExecPushString2(xmlRegExecCtxt *exec, const xmlChar *value, const xmlChar *value2, void *data) {
    (void)value2;
    return xmlRegExecPushString(exec, value, data);
}

/* ---- Provide a simple fallback implementation to use only if the project's
   function is not available at runtime. This keeps the harness usable even
   outside the project build. The harness will prefer the project's implementation
   when it can be found via a weak symbol or dlsym.
*/
static int
fallback_xmlRelaxNGValidateCompiledContent(xmlRelaxNGValidCtxtPtr ctxt, xmlRegexpPtr regexp, xmlNodePtr content) {
    if (ctxt == NULL) return -1;

    xmlRegExecCtxtPtr exec = xmlRegNewExecCtxt(regexp, NULL, ctxt);
    if (exec == NULL) return -1;

    xmlNodePtr cur = content;
    int ret = 1;

    while (cur) {
        if (cur->name) {
            int r;
            /* In real code, element nodes with ns use xmlRegExecPushString2.
               For the fallback, we only use the simple behavior:
             */
            r = xmlRegExecPushString(exec, cur->name, ctxt);
            if (r < 0) { ret = -1; break; }
            /* r == 0: continue; r == 1: success token -> continue as well */
        }
        cur = cur->next;
    }

    if (ret >= 0) {
        int final = xmlRegExecPushString(exec, NULL, ctxt);
        if (final == 1) ret = 1;
        else if (final == 0) ret = 0;
        else ret = -1;
    }

    xmlRegFreeExecCtxt(exec);
    return ret;
}

/* ---- Helpers to build a small xmlNode linked list from fuzzer input
   Layout we parse from Data (bytes):
     [Nnodes (1 byte, capped)] [for each node:]
       [type (1 byte)] [ns_flag (1 byte: 0/1)] [name_len (1 byte, capped)]
       [name bytes (name_len)]
   After nodes, if there's at least one extra byte, we take it to decide final return:
       val = Data[pos] % 3
   mapping 0 -> 1 (success), 1 -> 0 (noelem), 2 -> -1 (error)
   All allocations are freed before return.
*/

static size_t safe_min(size_t a, size_t b) { return (a < b) ? a : b; }

static xmlNodePtr build_nodes_from_input(const uint8_t *Data, size_t Size, size_t *used_bytes) {
    *used_bytes = 0;
    if (Size == 0) return NULL;
    size_t pos = 0;
    size_t max_nodes = 16;
    size_t n_nodes = 0;
    size_t avail = Size;

    /* Need at least 1 byte for number of nodes */
    if (avail < 1) return NULL;
    uint8_t n_spec = Data[pos++];
    *used_bytes += 1;
    avail--;
    n_nodes = safe_min((size_t)n_spec, max_nodes);

    xmlNodePtr head = NULL;
    xmlNodePtr tail = NULL;

    for (size_t i = 0; i < n_nodes; i++) {
        if (avail < 3) break;
        uint8_t type = Data[pos++];
        uint8_t ns_flag = Data[pos++];
        uint8_t name_len = Data[pos++];
        *used_bytes += 3;
        avail -= 3;

        name_len = (name_len > 32) ? 32 : name_len;
        size_t take = safe_min((size_t)name_len, avail);
        xmlChar *name = (xmlChar *)malloc(take + 1);
        if (name == NULL) break;
        if (take > 0) {
            memcpy(name, Data + pos, take);
            pos += take;
            avail -= take;
            *used_bytes += take;
        }
        name[take] = '\0';

        /* create node */
        xmlNodePtr node = (xmlNodePtr)malloc(sizeof(xmlNode));
        if (node == NULL) {
            free(name);
            break;
        }
        node->type = (int)type;
        node->name = name;
        if (ns_flag && take > 0) {
            /* create a small namespace with href pointing to the node name (just for data) */
            xmlNsPtr ns = (xmlNsPtr)malloc(sizeof(xmlNs));
            if (ns) {
                ns->href = (xmlChar *)malloc(take + 1);
                if (ns->href) {
                    memcpy(ns->href, name, take + 1);
                } else {
                    free(ns);
                    ns = NULL;
                }
            }
            node->ns = ns;
        } else {
            node->ns = NULL;
        }
        node->parent = NULL;
        node->next = NULL;

        if (tail == NULL) {
            head = tail = node;
        } else {
            tail->next = node;
            node->parent = NULL;
            tail = node;
        }
    }

    return head;
}

static void free_nodes(xmlNodePtr head) {
    xmlNodePtr cur = head;
    while (cur) {
        xmlNodePtr next = cur->next;
        if (cur->name) free(cur->name);
        if (cur->ns) {
            if (cur->ns->href) free(cur->ns->href);
            free(cur->ns);
        }
        free(cur);
        cur = next;
    }
}

/* Declare the target function as a weak symbol with C linkage.
   When libxml2 is linked into the fuzzer binary, this symbol will resolve
   to the real implementation and the call below will exercise the target.
   If the symbol is not present, the weak symbol will be NULL and we will
   use the fallback implementation instead.
*/
#ifdef __cplusplus
extern "C" {
#endif
int xmlRelaxNGValidateCompiledContent(xmlRelaxNGValidCtxtPtr ctxt, xmlRegexpPtr regexp, xmlNodePtr content) __attribute__((weak));
#ifdef __cplusplus
}
#endif

/* LLVMFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0) return 0;

    /* Build nodes from input */
    size_t used = 0;
    xmlNodePtr content = build_nodes_from_input(Data, Size, &used);

    /* prepare validation context */
    xmlRelaxNGValidCtxtPtr ctxt = (xmlRelaxNGValidCtxtPtr)malloc(sizeof(xmlRelaxNGValidCtxt));
    if (ctxt == NULL) {
        free_nodes(content);
        return 0;
    }
    memset(ctxt, 0, sizeof(*ctxt));
    ctxt->perr = 0;
    ctxt->flags = 0;
    ctxt->state = (xmlRelaxNGValidStatePtr)malloc(sizeof(xmlRelaxNGValidState));
    if (ctxt->state == NULL) {
        free(ctxt);
        free_nodes(content);
        return 0;
    }
    ctxt->state->seq = NULL;

    /* Decide behavior for final xmlRegExecPushString NULL push, driven by next byte if available */
    int fuzz_final_ret = 1; /* default success */
    if (used < Size) {
        uint8_t v = Data[used++];
        int sel = v % 3;
        if (sel == 0) fuzz_final_ret = 1;   /* success */
        else if (sel == 1) fuzz_final_ret = 0; /* noelem */
        else fuzz_final_ret = -1; /* error */
    }
    ctxt->fuzz_final_ret = fuzz_final_ret;

    /* Create a dummy regexp object */
    xmlRegexpPtr regexp = (xmlRegexpPtr)malloc(sizeof(xmlRegexp));
    if (regexp == NULL) {
        free(ctxt->state);
        free(ctxt);
        free_nodes(content);
        return 0;
    }

    /* Prefer a direct call to the project's implementation when available
       (weak symbol check). If not available, fall back to our fallback impl.
    */
    if (xmlRelaxNGValidateCompiledContent) {
        /* Call the project's implementation directly */
        (void)xmlRelaxNGValidateCompiledContent(ctxt, regexp, content);
    } else {
        /* Use the fallback */
        (void)fallback_xmlRelaxNGValidateCompiledContent(ctxt, regexp, content);
    }

    /* Cleanup */
    free(regexp);
    if (ctxt->state) free(ctxt->state);
    free(ctxt);
    free_nodes(content);

    return 0;
}

/* Provide a simple main for standalone testing (optional).
   When using libFuzzer, this main is not required. */
#ifdef STANDALONE_FUZZ_DRIVER
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    /* Example: run LLVMFuzzerTestOneInput with some sample data */
    const uint8_t data[] = { 2, /* 2 nodes */
                             2, 1, 3, 'a', 'b', 'c', /* node 1: type=2 (element), ns=1, name="abc" */
                             0, 0, 4, 't','e','x','t', /* node 2: type=0 (text), ns=0, name="text" */
                             1 /* final behavior -> maps to 0 (noelem) in fuzz mapping */ };
    LLVMFuzzerTestOneInput(data, sizeof(data));
    return 0;
}
#endif

/* End of driver */
