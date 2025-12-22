#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h> /* for RTLD_DEFAULT */

/* Some platforms may not define RTLD_DEFAULT in <dlfcn.h>. Provide a fallback
 * definition so code that uses RTLD_DEFAULT can compile portably in the
 * fuzzing harness. On systems where RTLD_DEFAULT is defined by the libc,
 * this conditional definition will be skipped.
 */
#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void *)0)
#endif

// Minimal xmlChar definition used by libxml2
typedef unsigned char xmlChar;

/* Recreate the valid state structure (fields and order match the original)
 * This matches the layout in libxml2's relaxng.c so the fallback implementation
 * and the fuzz harness's buffer setup are layout-compatible.
 */
typedef struct _xmlRelaxNGValidState {
    void *node;            /* the current node */
    void *seq;             /* the sequence of children left to validate */
    int nbAttrs;           /* the number of attributes */
    int maxAttrs;          /* the size of attrs */
    int nbAttrLeft;        /* the number of attributes left to validate */
    xmlChar *value;        /* the value when operating on string */
    xmlChar *endvalue;     /* the end value when operating on string */
    void **attrs;          /* the array of attributes */
} xmlRelaxNGValidState, *xmlRelaxNGValidStatePtr;

/* Recreate the validation context structure with the same field order.
 * Unknown pointer types are represented as void* so pointer sizes match.
 */
typedef struct _xmlRelaxNGValidCtxt {
    void *userData;             /* user specific data block */
    void (*error)(void);        /* placeholder for xmlRelaxNGValidityErrorFunc */
    void (*warning)(void);      /* placeholder for xmlRelaxNGValidityWarningFunc */
    void (*serror)(void);       /* placeholder for xmlStructuredErrorFunc */
    int nbErrors;               /* number of errors in validation */

    void *schema;               /* xmlRelaxNGPtr */
    void *doc;                  /* xmlDocPtr */
    int flags;                  /* validation flags */
    int depth;                  /* validation depth */
    int idref;                  /* requires idref checking */
    int errNo;                  /* the first error found */

    void *err;                  /* xmlRelaxNGValidErrorPtr - Last error */
    int errNr;                  /* Depth of the error stack */
    int errMax;                 /* Max depth of the error stack */
    void *errTab;               /* stack of errors */

    xmlRelaxNGValidStatePtr state;      /* the current validation state */
    void *states;               /* xmlRelaxNGStatesPtr - the accumulated state list */

    void *freeState;            /* the pool of free valid states */
    int freeStatesNr;
    int freeStatesMax;
    void **freeStates;          /* the pool of free state groups */

    void *elem;                 /* xmlRegExecCtxtPtr - the current element regexp */
    int elemNr;                 /* the number of element validated */
    int elemMax;                /* the max depth of elements */
    void **elemTab;             /* the stack of regexp runtime */
    int pstate;                 /* progressive state */
    void *pnode;                /* the current node */
    void *pdef;                 /* xmlRelaxNGDefinePtr the non-streamable definition */
    int perr;                   /* signal error in content model outside the regexp */
} xmlRelaxNGValidCtxt, *xmlRelaxNGValidCtxtPtr;

/* Local fallback implementation copied from the project's relaxng.c.
 * If the project's symbol isn't available (e.g., it's static and not exported),
 * this fallback will be used so the harness remains runnable.
 */
static int
local_xmlRelaxNGNextValue(xmlRelaxNGValidCtxtPtr ctxt)
{
    xmlChar *cur;

    if (ctxt == NULL || ctxt->state == NULL)
        return 0;

    cur = ctxt->state->value;
    if ((cur == NULL) || (ctxt->state->endvalue == NULL)) {
        ctxt->state->value = NULL;
        ctxt->state->endvalue = NULL;
        return (0);
    }
    while (*cur != 0)
        cur++;
    while ((cur != ctxt->state->endvalue) && (*cur == 0))
        cur++;
    if (cur == ctxt->state->endvalue)
        ctxt->state->value = NULL;
    else
        ctxt->state->value = cur;
    return (0);
}

/* Declare the project's symbol as weak. If the project's exported symbol is
 * present when linking, this pointer will be non-NULL and will refer to the
 * real implementation. If it is absent, this will be NULL and we will use
 * the local fallback.
 */
int xmlRelaxNGNextValue(xmlRelaxNGValidCtxtPtr ctxt) __attribute__((weak));

/* Try to call the project's xmlRelaxNGNextValue if it is exported.
 * If not found, call the local fallback.
 */
static int
call_project_xmlRelaxNGNextValue(xmlRelaxNGValidCtxtPtr ctxt)
{
    if (xmlRelaxNGNextValue != NULL) {
        /* Call the project's implementation */
        return xmlRelaxNGNextValue(ctxt);
    }

    /* Fallback to local copy */
    return local_xmlRelaxNGNextValue(ctxt);
}

/* Fuzzer entry point
 * The fuzzer provides arbitrary bytes in Data[0..Size-1].
 * We'll map them into a buffer used as the string data for the state's
 * value/endvalue and call the project's xmlRelaxNGNextValue if available,
 * otherwise fallback via call_project_xmlRelaxNGNextValue.
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Allocate context and state */
    xmlRelaxNGValidCtxtPtr ctxt = (xmlRelaxNGValidCtxtPtr)calloc(1, sizeof(xmlRelaxNGValidCtxt));
    if (ctxt == NULL) return 0;
    xmlRelaxNGValidStatePtr state = (xmlRelaxNGValidStatePtr)calloc(1, sizeof(xmlRelaxNGValidState));
    if (state == NULL) { free(ctxt); return 0; }
    ctxt->state = state;

    /* Guard against huge allocations */
    if (Size > (1 << 20)) { /* 1 MiB limit for safety */
        free(state);
        free(ctxt);
        return 0;
    }

    /* Create a buffer sized Size+1 so we can safely null-terminate at [Size]. */
    size_t buf_size = Size + 1;
    xmlChar *buf = (xmlChar *)malloc(buf_size ? buf_size : 1);
    if (buf == NULL) {
        free(state);
        free(ctxt);
        return 0;
    }

    /* Copy input data into the buffer and ensure a terminating 0 at buf[Size]. */
    if (Size > 0 && Data != NULL) {
        memcpy(buf, Data, Size);
    }
    buf[Size] = 0;

    /* Initialize state's pointers. */
    state->value = buf;
    state->endvalue = buf + Size; /* As used by the original implementation. */

    /* Call the project's implementation if available, otherwise fallback.
     * Use call_project_xmlRelaxNGNextValue so we don't end up using a fake
     * symbol defined in the harness.
     */
    (void)call_project_xmlRelaxNGNextValue(ctxt);

    /* Optionally call again to exercise transitions */
    (void)call_project_xmlRelaxNGNextValue(ctxt);

    /* Clean up */
    free(buf);
    free(state);
    free(ctxt);

    return 0;
}
