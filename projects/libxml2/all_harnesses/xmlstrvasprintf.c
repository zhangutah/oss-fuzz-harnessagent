#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

/* Use public libxml2 headers for types and xmlFree */
#include <libxml/xmlstring.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h> /* for xmlInitParser */

/* Forward declaration for the private function we fuzz.
   We avoid including the private header which uses XML_HIDDEN
   (not defined here). */
int xmlStrVASPrintf(xmlChar **out, int maxSize, const char *msg, va_list ap);

#define MAX_STR_ARGS 16
#define MAX_MSG_LEN 512
#define MAX_STR_LEN 256

/* Variadic wrapper that creates a va_list and forwards it to xmlStrVASPrintf */
static int
call_xmlStrVASPrintf_with_varargs(xmlChar **out, int maxSize, const char *msg, ...)
{
    int ret;
    va_list ap;
    va_start(ap, msg);
    ret = xmlStrVASPrintf(out, maxSize, msg, ap);
    va_end(ap);
    return ret;
}

#ifdef __cplusplus
extern "C" {
#endif

/* Optional initializer called by libFuzzer once at startup.
   Initialize libxml2 so its code paths can be exercised. */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* Initialize parser (and other global state). */
    xmlInitParser();
    return 0;
}

/* Fuzzer entry point expected by libFuzzer / AFL++ with LLVMFuzzerTestOneInput */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    /* Quick checks */
    if (Data == NULL || Size < 1)
        return 0;

    size_t pos = 0;

    /* Extract maxSize from the first byte */
    int maxSize = (int)Data[pos++];
    /* Bound maxSize to reasonable values */
    if (maxSize < -1024) maxSize = -1024;
    if (maxSize > 65536) maxSize = 65536;

    /* Determine number of %s arguments to place in the format string */
    unsigned n_args = 0;
    if (pos < Size) {
        n_args = Data[pos++] % (MAX_STR_ARGS + 1); /* 0 .. MAX_STR_ARGS */
    }

    /* Build the format string consisting only of %s specifiers separated by spaces.
       This ensures we only pass char* arguments, avoiding unsafe type mismatches. */
    char msgbuf[MAX_MSG_LEN];
    size_t msglen = 0;
    msgbuf[0] = '\0';

    /* Prepare storage for the argument strings */
    char *args[MAX_STR_ARGS];
    for (unsigned i = 0; i < MAX_STR_ARGS; ++i)
        args[i] = NULL;

    for (unsigned i = 0; i < n_args && pos < Size; ++i) {
        /* Append "%s" (and a space if not the last) */
        const char *tok = "%s";
        size_t toklen = strlen(tok);
        if (msglen + toklen + 2 < sizeof(msgbuf)) {
            memcpy(msgbuf + msglen, tok, toklen);
            msglen += toklen;
            if (i + 1 < n_args) {
                msgbuf[msglen++] = ' ';
            }
            msgbuf[msglen] = '\0';
        } else {
            /* no space to append more */
            break;
        }

        /* Determine string length for this argument from the input (1 .. MAX_STR_LEN)
           and copy the following bytes. Important: consume the selector byte first,
           then compute remaining bytes available for copying. */
        if (pos >= Size) {
            args[i] = (char *)malloc(1);
            if (args[i]) args[i][0] = '\0';
            continue;
        }

        /* Consume selector byte to choose length, then compute remaining bytes */
        uint8_t selector = Data[pos++];
        size_t remaining = (pos <= Size) ? (Size - pos) : 0; /* bytes available after the selector byte */
        size_t str_len = 1 + (selector % MAX_STR_LEN); /* at least 1 char */
        if (str_len > remaining)
            str_len = remaining;

        /* Allocate and copy (ensure NUL termination) */
        args[i] = (char *)malloc(str_len + 1);
        if (args[i] == NULL) {
            /* Allocation failed; set to empty string */
            args[i] = (char *)malloc(1);
            if (args[i]) args[i][0] = '\0';
            continue;
        }
        if (str_len > 0) {
            memcpy(args[i], Data + pos, str_len);
            pos += str_len;
        }
        args[i][str_len] = '\0';
    }

    /* If no specifiers were added, make the format a simple string (use a short literal or an extracted string)
       Important security fix: do NOT use raw input bytes as the format string (they may contain '%' sequences).
       Instead, use "%s" as the format and pass the extracted bytes as an argument. */
    if (msgbuf[0] == '\0') {
        /* Try to build a small literal or use part of input as the message */
        if (Size - pos >= 1) {
            size_t lit_len = (Size - pos > 31) ? 31 : (Size - pos);
            if (lit_len >= MAX_MSG_LEN) lit_len = MAX_MSG_LEN - 1;

            /* Allocate args[0] to hold the extracted literal, and use "%s" as msgbuf */
            args[0] = (char *)malloc(lit_len + 1);
            if (args[0]) {
                memcpy(args[0], (const char *)(Data + pos), lit_len);
                args[0][lit_len] = '\0';
            } else {
                /* fallback to an empty string if allocation fails */
                args[0] = (char *)malloc(1);
                if (args[0]) args[0][0] = '\0';
            }
            pos += lit_len;
            /* Use a safe format string */
            strncpy(msgbuf, "%s", sizeof(msgbuf) - 1);
            msgbuf[sizeof(msgbuf) - 1] = '\0';
        } else {
            strncpy(msgbuf, "fuzz", sizeof(msgbuf) - 1);
            msgbuf[sizeof(msgbuf) - 1] = '\0';
        }
    }

    /* Prepare the output pointer */
    xmlChar *out = NULL;

    /* Use remaining bytes in a volatile sink so the input influences program state
       and cannot be optimized away. This helps the fuzzer's coverage instrumentation. */
    static volatile uint64_t data_sink = 0;
    for (size_t i = pos; i < Size; ++i) {
        data_sink = (data_sink * 1315423911u) + Data[i] + 1;
    }

    /* Call the wrapper forwarding varargs. We always pass MAX_STR_ARGS pointers (some may be NULL).
       To avoid passing NULL for %s arguments, substitute an empty string literal for any NULL arg. */
    int ret = call_xmlStrVASPrintf_with_varargs(&out, maxSize, msgbuf,
                                                args[0] ? args[0] : "",
                                                args[1] ? args[1] : "",
                                                args[2] ? args[2] : "",
                                                args[3] ? args[3] : "",
                                                args[4] ? args[4] : "",
                                                args[5] ? args[5] : "",
                                                args[6] ? args[6] : "",
                                                args[7] ? args[7] : "",
                                                args[8] ? args[8] : "",
                                                args[9] ? args[9] : "",
                                                args[10] ? args[10] : "",
                                                args[11] ? args[11] : "",
                                                args[12] ? args[12] : "",
                                                args[13] ? args[13] : "",
                                                args[14] ? args[14] : "",
                                                args[15] ? args[15] : "");

    /* Clean up: free any allocated argument strings */
    for (unsigned i = 0; i < MAX_STR_ARGS; ++i) {
        if (args[i]) {
            free(args[i]);
            args[i] = NULL;
        }
    }

    /* If xmlStrVASPrintf allocated an output buffer, free it with xmlFree */
    if (out != NULL) {
        /* xmlFree is provided by libxml2 (xmlmemory.h) */
        xmlFree(out);
        out = NULL;
    }

    /* Use ret in a way that prevents its removal (though not necessary typically) */
    (void)ret;
    (void)data_sink;

    return 0;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
