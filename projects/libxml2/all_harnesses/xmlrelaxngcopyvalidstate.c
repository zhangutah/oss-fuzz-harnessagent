// Fuzz driver for:
// xmlRelaxNGValidStatePtr xmlRelaxNGCopyValidState(xmlRelaxNGValidCtxtPtr ctxt, xmlRelaxNGValidStatePtr state);
//
// Fix: Avoid letting the library cache freed states inside the fuzzer-provided validation
// context, which can cause unbounded memory growth across fuzzing iterations.
// When freeing the copied state, call xmlRelaxNGFreeValidState(NULL, ret) so the
// library will actually free the memory instead of storing it in ctxt->freeState.
//
// This driver includes the implementation of relaxng.c so it can call the static function directly.
// It constructs minimal valid-looking xmlRelaxNGValidCtxt and xmlRelaxNGValidState instances
// from the fuzzer input and calls xmlRelaxNGCopyValidState, then frees returned state.
//
// Note: This file expects to be compiled in-tree with the libxml2 sources available
// at /src/libxml2 (so the path to relaxng.c used below matches the workspace layout).

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

/*
 * Include the implementation to get access to the static functions and types.
 * Using the absolute path observed in the workspace.
 */
#include "/src/libxml2/relaxng.c"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Basic sanity: need at least 1 byte to drive decisions. */
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser environment (safe to call multiple times). */
    xmlInitParser();

    /* Allocate and zero a validation context. The struct definition is inside relaxng.c. */
    xmlRelaxNGValidCtxtPtr vctxt = (xmlRelaxNGValidCtxtPtr)calloc(1, sizeof(struct _xmlRelaxNGValidCtxt));
    if (vctxt == NULL)
        return 0;

    /* Make sure fields used by memory error handling are sane */
    vctxt->serror = NULL;
    vctxt->error = NULL;
    vctxt->userData = NULL;

    /*
     * Avoid enabling the internal free-state caching across fuzz iterations.
     * The library will create ctxt->freeState lazily when xmlRelaxNGFreeValidState
     * is invoked with a non-NULL ctxt. To prevent the library from caching
     * states inside the fuzzer-held context (which would leak across runs),
     * we will pass NULL as the ctxt when freeing copied states below.
     *
     * Keep vctxt->freeState NULL to reflect a fresh context.
     */
    vctxt->freeState = NULL;

    /* Prepare a source state to copy */
    xmlRelaxNGValidStatePtr state = (xmlRelaxNGValidStatePtr)calloc(1, sizeof(xmlRelaxNGValidState));
    if (state == NULL) {
        free(vctxt);
        return 0;
    }

    /* Use first byte to determine number of attributes (bounded small) */
    unsigned int nbAttrs = Data[0] % 6; /* up to 5 attrs */
    state->nbAttrs = nbAttrs;
    state->nbAttrLeft = nbAttrs;

    /* If nbAttrs > 0, allocate attrs array and fill with some pointers (NULLs are fine) */
    if (nbAttrs > 0) {
        state->maxAttrs = (int)(nbAttrs);
        state->attrs = (xmlAttrPtr *)malloc(sizeof(xmlAttrPtr) * (size_t)state->maxAttrs);
        if (state->attrs == NULL) {
            /* cleanup */
            free(state);
            free(vctxt);
            return 0;
        }
        for (unsigned int i = 0; i < nbAttrs; i++) {
            /* Populate attribute pointers with NULL or simple dummy xmlAttr nodes.
             * To keep things safe we set them to NULL which is accepted by copy code. */
            state->attrs[i] = NULL;
        }
    } else {
        state->maxAttrs = 0;
        state->attrs = NULL;
    }

    /* Use a bit of the input for value string if available (to exercise string copying checks) */
    if (Size > 1) {
        /* limit string length small */
        size_t strLen = (Size - 1) > 64 ? 64 : (Size - 1);
        xmlChar *val = (xmlChar *)malloc(strLen + 1);
        if (val != NULL) {
            memcpy(val, Data + 1, strLen);
            val[strLen] = '\0';
            state->value = val;
            state->endvalue = val + strLen;
        }
    } else {
        state->value = NULL;
        state->endvalue = NULL;
    }

    /* node/seq fields: keep NULL (safe for copy/equality routines used later) */
    state->node = NULL;
    state->seq = NULL;

    /*
     * Call the function under test.
     * xmlRelaxNGCopyValidState is static in relaxng.c but available because we included the .c.
     */
    xmlRelaxNGValidStatePtr ret = xmlRelaxNGCopyValidState(vctxt, state);

    /* If copy allocated something, free it via the library internal free to mirror normal usage.
     * IMPORTANT: pass NULL as ctxt to force the library to actually free the memory instead
     * of caching it inside the fuzzer's vctxt (which would grow unbounded across iterations). */
    if (ret != NULL) {
        xmlRelaxNGFreeValidState(NULL, ret);
    }

    /* Free original state's resources */
    if (state->attrs != NULL) {
        free(state->attrs);
        state->attrs = NULL;
    }
    if (state->value != NULL) {
        free(state->value);
        state->value = NULL;
    }
    free(state);

    /* free validation context (we didn't use internal free-state caching) */
    free(vctxt);

    /* Cleanup libxml (no-op if not desired) */
    xmlCleanupParser();

    return 0;
}

#ifdef __cplusplus
}
#endif

/*
 * Optionally provide a main to allow running the harness standalone (not used by libFuzzer).
 * If compiled standalone, it will read stdin into a buffer and invoke the fuzzer entry.
 */
#ifdef FUZZ_MAIN
#include <stdio.h>
int main(int argc, char **argv) {
    /* read all stdin */
    fseek(stdin, 0, SEEK_END);
    long len = ftell(stdin);
    if (len <= 0) return 0;
    fseek(stdin, 0, SEEK_SET);
    uint8_t *buf = (uint8_t*)malloc(len);
    if (!buf) return 0;
    if (fread(buf, 1, len, stdin) != (size_t)len) {
        free(buf);
        return 0;
    }
    LLVMFuzzerTestOneInput(buf, (size_t)len);
    free(buf);
    return 0;
}
#endif