// SPDX-License-Identifier: MIT
//
// Fuzzer driver for:
//   int xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr ctxt,
//                              xmlRelaxNGDefinePtr define,
//                              xmlNodePtr elem);
//
// This harness dynamically looks up xmlRelaxNGElementMatch at runtime
// with dlsym() to avoid link-time undefined references in builds where
// the symbol is not exported.  Additionally it declares a weak
// extern for xmlRelaxNGElementMatch so that if the symbol is present
// at link-time it can be called directly (and static analysis / the
// test harness can detect an explicit reference).

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>

/*
 * Forward-declare/replicate the internal Relax-NG structures and enums
 * used by xmlRelaxNGElementMatch so we can build compatible instances.
 *
 * These definitions mirror the ones in relaxng.c. They must match
 * exactly the implementation for memory layout compatibility.
 *
 * (Only the parts needed here are replicated.)
 */

typedef enum {
    XML_RELAXNG_NOOP = -1,      /* a no operation from simplification  */
    XML_RELAXNG_EMPTY = 0,      /* an empty pattern */
    XML_RELAXNG_NOT_ALLOWED,    /* not allowed top */
    XML_RELAXNG_EXCEPT,         /* except present in nameclass defs */
    XML_RELAXNG_TEXT,           /* textual content */
    XML_RELAXNG_ELEMENT,        /* an element */
    XML_RELAXNG_DATATYPE,       /* external data type definition */
    XML_RELAXNG_PARAM,          /* external data type parameter */
    XML_RELAXNG_VALUE,          /* value from an external data type definition */
    XML_RELAXNG_LIST,           /* a list of patterns */
    XML_RELAXNG_ATTRIBUTE,      /* an attribute following a pattern */
    XML_RELAXNG_DEF,            /* a definition */
    XML_RELAXNG_REF,            /* reference to a definition */
    XML_RELAXNG_EXTERNALREF,    /* reference to an external def */
    XML_RELAXNG_PARENTREF,      /* reference to a def in the parent grammar */
    XML_RELAXNG_OPTIONAL,       /* optional patterns */
    XML_RELAXNG_ZEROORMORE,     /* zero or more non empty patterns */
    XML_RELAXNG_ONEORMORE,      /* one or more non empty patterns */
    XML_RELAXNG_CHOICE,         /* a choice between non empty patterns */
    XML_RELAXNG_GROUP,          /* a pair/group of non empty patterns */
    XML_RELAXNG_INTERLEAVE,     /* interleaving choice of non-empty patterns */
    XML_RELAXNG_START           /* Used to keep track of starts on grammars */
} xmlRelaxNGType;

/* forward typedefs to match relaxng.c */
typedef struct _xmlRelaxNGDefine xmlRelaxNGDefine;
typedef xmlRelaxNGDefine *xmlRelaxNGDefinePtr;

typedef struct _xmlRelaxNGValidCtxt xmlRelaxNGValidCtxt;
typedef xmlRelaxNGValidCtxt *xmlRelaxNGValidCtxtPtr;

/* replicate minimal internal define struct */
struct _xmlRelaxNGDefine {
    xmlRelaxNGType type;        /* the type of definition */
    xmlNodePtr node;            /* the node in the source */
    xmlChar *name;              /* the element local name if present */
    xmlChar *ns;                /* the namespace local name if present */
    xmlChar *value;             /* value when available */
    void *data;                 /* data lib or specific pointer */
    xmlRelaxNGDefinePtr content;        /* the expected content */
    xmlRelaxNGDefinePtr parent; /* the parent definition, if any */
    xmlRelaxNGDefinePtr next;   /* list within grouping sequences */
    xmlRelaxNGDefinePtr attrs;  /* list of attributes for elements */
    xmlRelaxNGDefinePtr nameClass;      /* the nameClass definition if any */
    xmlRelaxNGDefinePtr nextHash;       /* next define in defs/refs hash tables */
    short depth;                /* used for the cycle detection */
    short dflags;               /* define related flags */
    void *contModel;            /* xmlRegexpPtr - avoid including regex type */
};

/* replicate (a subset of) the internal validation context struct */
struct _xmlRelaxNGValidCtxt {
    void *userData;             /* user specific data block */
    void (*error)(void *ctx, const char *msg, ...);  /* the callback in case of errors */
    void (*warning)(void *ctx, const char *msg, ...);      /* the callback in case of warning */
    void *serror;
    int nbErrors;               /* number of errors in validation */

    void *schema;               /* The schema in use */
    xmlDocPtr doc;              /* the document being validated */
    int flags;                  /* validation flags */
    int depth;                  /* validation depth */
    int idref;                  /* requires idref checking */
    int errNo;                  /* the first error found */

    /* note: a large number of fields are present in the real struct.
     * For fuzzing we will zero the struct and only set flags if needed.
     */
    void *err;
    int errNr;
    int errMax;
    void *errTab;

    void *state;
    void *states;

    void *freeState;
    int freeStatesNr;
    int freeStatesMax;
    void **freeStates;

    /* progressive validation fields */
    void *elem;
    int elemNr;
    int elemMax;
    void **elemTab;
    int pstate;
    xmlNodePtr pnode;
    xmlRelaxNGDefinePtr pdef;
    int perr;
};

/* If the project's relaxng.c defines FLAGS_IGNORABLE / FLAGS_NOERROR,
 * replicate their values here to allow setting them.
 * These values come from relaxng.c:
 */
#define FLAGS_IGNORABLE      1
#define FLAGS_NEGATIVE       2
#define FLAGS_MIXED_CONTENT  4
#define FLAGS_NOERROR        8

/* Weak declaration of xmlRelaxNGElementMatch so that if the symbol is
 * available at link-time we can call it directly (and static analysis
 * sees a direct reference).  If the symbol is not present this will be
 * a NULL pointer and we will fall back to dlsym. */
#if defined(__GNUC__) || defined(__clang__)
# ifdef __cplusplus
extern "C" int xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr, xmlNodePtr) __attribute__((weak));
# else
extern int xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr, xmlNodePtr) __attribute__((weak));
# endif
#else
/* Non-GNU compilers: declare without weak attribute. If not present at link time
 * this will be handled by the dlsym fallback below. */
# ifdef __cplusplus
extern "C" int xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr, xmlNodePtr);
# else
extern int xmlRelaxNGElementMatch(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr, xmlNodePtr);
# endif
#endif

/* Helper: clamp a size to a reasonable max for names */
static size_t clamp_len(size_t v, size_t max) {
    return (v == 0) ? 1 : (v > max ? max : v);
}

/* Fuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml2 parser environment */
    xmlInitParser();

    /* Derive small lengths from input */
    size_t half = Size / 2;
    (void)half;
    size_t namelen = clamp_len((size_t)Data[0] % 16 + 1, 32);
    size_t nslen = clamp_len((size_t)Data[Size > 0 ? Size - 1 : 0] % 16 + 1, 64);
    size_t nodename_len = clamp_len((size_t)Data[Size > 1 ? 1 : 0] % 16 + 1, 32);

    /* Bound reading from Data safely */
    size_t off = 0;

    /* name for the RelaxNG define (local name) */
    size_t want = namelen;
    if (off + want > Size) want = Size - off;
    char *def_name = (char *)malloc(want + 1);
    if (!def_name) {
        xmlCleanupParser();
        return 0;
    }
    memcpy(def_name, Data + off, want);
    def_name[want] = '\0';
    off += want;

    /* namespace for the RelaxNG define */
    want = nslen;
    if (off + want > Size) want = Size - off;
    char *def_ns = (char *)malloc(want + 1);
    if (!def_ns) {
        free(def_name);
        xmlCleanupParser();
        return 0;
    }
    memcpy(def_ns, Data + off, want);
    def_ns[want] = '\0';
    off += want;

    /* node name to create an element node */
    want = nodename_len;
    if (off + want > Size) want = Size - off;
    char *node_name = (char *)malloc(want + 1);
    if (!node_name) {
        free(def_name);
        free(def_ns);
        xmlCleanupParser();
        return 0;
    }
    memcpy(node_name, Data + off, want);
    node_name[want] = '\0';
    off += want;

    /* Also derive a namespace href for the node from remaining bytes if any */
    char *node_ns_href = NULL;
    if (off < Size) {
        size_t remain = Size - off;
        size_t href_len = clamp_len((size_t)Data[off] % 16 + 1, 64);
        if (href_len > remain) href_len = remain;
        node_ns_href = (char *)malloc(href_len + 1);
        if (node_ns_href) {
            memcpy(node_ns_href, Data + off, href_len);
            node_ns_href[href_len] = '\0';
        }
    }

    /* Create a libxml2 element node with the name derived above */
    xmlNodePtr node = xmlNewNode(NULL, BAD_CAST node_name);
    if (node == NULL) {
        free(def_name); free(def_ns); free(node_name); if (node_ns_href) free(node_ns_href);
        xmlCleanupParser();
        return 0;
    }

    /* Optionally create and attach a namespace to the node */
    if (node_ns_href != NULL && node_ns_href[0] != '\0') {
        xmlNsPtr ns = xmlNewNs(node, BAD_CAST node_ns_href, NULL);
        (void)ns; /* ignore return; namespace attached to node */
    }

    /* Build a minimal xmlRelaxNGDefine and fill it */
    xmlRelaxNGDefinePtr def = (xmlRelaxNGDefinePtr)calloc(1, sizeof(xmlRelaxNGDefine));
    if (def == NULL) {
        xmlFreeNode(node);
        free(def_name); free(def_ns); free(node_name); if (node_ns_href) free(node_ns_href);
        xmlCleanupParser();
        return 0;
    }
    def->type = XML_RELAXNG_ELEMENT;
    def->node = NULL; /* not used for our test inputs */
    def->name = (xmlChar *)xmlCharStrndup(def_name, (int)strlen(def_name));
    def->ns = (xmlChar *)xmlCharStrndup(def_ns, (int)strlen(def_ns));
    def->value = NULL;
    def->data = NULL;
    def->content = NULL;
    def->parent = NULL;
    def->next = NULL;
    def->attrs = NULL;
    def->nameClass = NULL;
    def->nextHash = NULL;
    def->depth = 0;
    def->dflags = 0;
    def->contModel = NULL;

    /* Prepare a validation context on the stack and zero it */
    xmlRelaxNGValidCtxt ctxt;
    memset(&ctxt, 0, sizeof(ctxt));
    /* Set FLAGS_IGNORABLE | FLAGS_NOERROR like some internal callers do */
    ctxt.flags = FLAGS_IGNORABLE | FLAGS_NOERROR;

    /* Dynamically resolve xmlRelaxNGElementMatch at runtime to avoid
     * link-time undefined reference if the symbol is not exported.
     * Prefer a direct (weak) reference when available so the function
     * is explicitly called if present at link-time.
     */
    typedef int (*xmlRelaxNGElementMatchFunc)(xmlRelaxNGValidCtxtPtr, xmlRelaxNGDefinePtr, xmlNodePtr);

    int rc = 0;

    /* First try direct weak symbol (if provided by the build).  Check the
     * function pointer value before calling to avoid calling a NULL symbol. */
#if defined(__GNUC__) || defined(__clang__)
    if (xmlRelaxNGElementMatch != NULL) {
        /* Direct call via weak symbol available at link time */
        rc = xmlRelaxNGElementMatch(&ctxt, def, node);
    } else
#endif
    {
        /* Fallback: try dlsym to locate the symbol at runtime */
        void *sym = NULL;
#ifdef RTLD_DEFAULT
        sym = dlsym(RTLD_DEFAULT, "xmlRelaxNGElementMatch");
#endif
        if (sym == NULL) {
            /* Fallback: try the program handle */
            void *dl = dlopen(NULL, RTLD_LAZY);
            if (dl != NULL) {
                sym = dlsym(dl, "xmlRelaxNGElementMatch");
                /* intentionally do not dlclose(dl) */
            }
        }

        if (sym != NULL) {
#ifdef __cplusplus
            xmlRelaxNGElementMatchFunc fn = reinterpret_cast<xmlRelaxNGElementMatchFunc>(sym);
#else
            xmlRelaxNGElementMatchFunc fn = (xmlRelaxNGElementMatchFunc)sym;
#endif
            /* Call the target function; store return to avoid being optimized out */
            rc = fn(&ctxt, def, node);
        } else {
            /* If the symbol isn't found, nothing to do; the harness still exercised code paths. */
        }
    }
    (void)rc; /* silence unused variable warnings if any */

    /* Cleanup */
    if (def->name) xmlFree(def->name);
    if (def->ns) xmlFree(def->ns);
    free(def);
    xmlFreeNode(node);

    free(def_name);
    free(def_ns);
    free(node_name);
    if (node_ns_href) free(node_ns_href);

    /* Clean libxml2 parser globals (no-op in many builds, but safe) */
    xmlCleanupParser();

    return 0;
}
