// Fuzz harness for xmllintResourceLoader - use the project's implementation
// The fuzzer entry point is defined as follows:
// extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/xmlIO.h>
#include <libxml/xmlstring.h>
#include <libxml/tree.h>

// Provide a no-op implementation of xmllintShell so linking succeeds.
// xmllint.c refers to this function but the original implementation is in shell.c,
// which is not linked into this TU. A simple stub is sufficient for fuzzing.
void xmllintShell(xmlDoc *doc, const char *filename, FILE *output) {
    (void)doc;
    (void)filename;
    (void)output;
}

 // Include the xmllint.c source file from the project so that we call the
 // project's implementation of xmllintResourceLoader (which is declared
 // static in xmllint.c). Including the .c into this TU gives us access to
 // that static symbol for fuzzing.
 //
 // Note: the path is relative because this harness lives in /src/libxml2/fuzz/
 // and xmllint.c is in /src/libxml2/xmllint.c
#include "../xmllint.c"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Split input into two strings: URL and ID */
    size_t url_len = Size / 2;
    size_t id_len = Size - url_len;

    const size_t MAX_STR = 1 << 16;
    if (url_len > MAX_STR) url_len = MAX_STR;
    if (id_len > MAX_STR) id_len = MAX_STR;

    /* allocate enough space: ensure url has space for "a" + '\0' when url_len == 0 */
    size_t url_alloc = (url_len == 0) ? 2 : (url_len + 1);
    size_t id_alloc = id_len + 1; /* at least 1 when id_len == 0 */

    char *url = (char *)malloc(url_alloc);
    char *id = (char *)malloc(id_alloc);
    if (url == NULL || id == NULL) {
        free(url); free(id);
        return 0;
    }

    if (url_len > 0)
        memcpy(url, Data, url_len);
    url[url_len > 0 ? url_len : 1] = '\0'; /* place terminator in appropriate spot */

    if (id_len > 0)
        memcpy(id, Data + url_len, id_len);
    id[id_len] = '\0';

    if (url_len == 0) {
        /* url was allocated with space for 'a' and '\0' */
        url[0] = 'a';
        /* url[1] already set to '\0' above */
    }

    /* Use the xmllintState type from xmllint.c */
    xmllintState lint;
    memset(&lint, 0, sizeof(lint));

    /* Silence output */
    lint.errStream = fopen("/dev/null", "w");
    if (lint.errStream == NULL)
        lint.errStream = stderr;

    /* Let the loader use default path-based resolution via xmlNewInputFromUrl */
    lint.defaultResourceLoader = NULL;

    /* Prepare a simple path list so the loader will try ./<lastsegment> */
    lint.nbpaths = 1;
    lint.paths[0] = xmlStrdup((const xmlChar *) ".");
    lint.appOptions = 0; /* no tracing */

    xmlParserInputPtr out = NULL;

    /* Call the project's xmllintResourceLoader directly */
    (void) xmllintResourceLoader((void *)&lint,
                                 url, id,
                                 (xmlResourceType)0,
                                 (xmlParserInputFlags)0,
                                 &out);

    if (out != NULL) {
        /* If a new input was created, free it using libxml2 API */
        xmlFreeInputStream(out);
    }

    if (lint.paths[0] != NULL)
        xmlFree(lint.paths[0]);
    if (lint.errStream && lint.errStream != stderr)
        fclose(lint.errStream);

    free(url);
    free(id);

    return 0;
}