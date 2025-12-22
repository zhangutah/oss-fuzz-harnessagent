#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Include libxml2 internal headers so xmlParserCtxt and xmlNextChar are visible.
   Use absolute project paths discovered in the workspace. */
#include "/src/libxml2/include/libxml/parser.h"
#include "/src/libxml2/include/libxml/parserInternals.h"
/* Include error handling API so we can clear errors and avoid leaks */
#include "/src/libxml2/include/libxml/xmlerror.h"

/* Fuzzer entry point expected by libFuzzer/LLVMFuzzer */
extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Protect against NULL Data when Size == 0 per fuzzer contract. */
    const size_t PAD = 1024; /* padding to avoid xmlParserGrow being triggered */
    size_t buf_len = Size + PAD;

    /* Allocate a buffer large enough so xmlNextChar won't try to grow input. */
    unsigned char *buf = (unsigned char *)malloc(buf_len);
    if (buf == NULL)
        return 0;

    if (Size > 0 && Data != NULL) {
        memcpy(buf, Data, Size);
    }
    /* Zero the remainder (and any padding). Zero bytes are valid xmlChar values. */
    if (buf_len > Size)
        memset(buf + Size, 0, buf_len - Size);

    /* Prepare xmlParserInput and xmlParserCtxt structures.
       We zero-initialize them to avoid uninitialized fields. */
    xmlParserInput input_storage;
    memset(&input_storage, 0, sizeof(input_storage));

    input_storage.base = (const xmlChar *)buf;
    input_storage.cur  = (const xmlChar *)buf;
    input_storage.end  = (const xmlChar *)(buf + buf_len);
    input_storage.line = 1;
    input_storage.col  = 1;
    input_storage.consumed = 0;
    input_storage.buf = NULL; /* explicit, ensure xmlParserGrow sees NULL and returns safely */
    input_storage.filename = NULL;

    xmlParserCtxt ctxt_storage;
    memset(&ctxt_storage, 0, sizeof(ctxt_storage));

    /* Provide a valid (zero-initialized) SAX handler so error reporting
       code (xmlCtxtVErr) can safely read ctxt->sax without crashing. */
    static xmlSAXHandler default_sax;
    /* zero-initialized static struct => all function pointers NULL and
       initialized field == 0 (not XML_SAX2_MAGIC). That's safe. */

    ctxt_storage.input = &input_storage;
    ctxt_storage.userData = &ctxt_storage; /* default user data used by SAX callbacks */
    ctxt_storage.sax = &default_sax;

    /* It's useful to set some parser flags to safe defaults */
    ctxt_storage.options = 0;
    ctxt_storage.recovery = 1; /* be permissive in error handling */

    /* Call the target function under test.
       xmlNextChar reads/modifies ctxt->input->cur, line and col.
       We call it once; additional calls could be performed to consume more input. */
    xmlNextChar(&ctxt_storage);

    /* Clear any last error allocations to avoid leak sanitizer reports.
       Use the context-specific reset so errors stored in ctxt_storage.lastError
       are freed. */
    xmlCtxtResetLastError(&ctxt_storage);

    free(buf);
    return 0;
}
