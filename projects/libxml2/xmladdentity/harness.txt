#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/entities.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>

static char *make_string_from_data(const uint8_t *data, size_t len) {
    // Allocate +1 and NUL-terminate
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    if (len)
        memcpy(s, data, len);
    s[len] = '\0';
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Initialize libxml2 once
    static int initialized = 0;
    if (!initialized) {
        xmlInitParser();
        initialized = 1;
    }

    if (Data == NULL || Size == 0) return 0;

    // Use first byte as flags:
    // bits 0-2: small type selector (we'll map to typical entity types)
    // bit 3: extSubset (0 -> internal subset, 1 -> external subset)
    // bit 4: set_out (0 -> pass NULL for out, 1 -> pass &out)
    uint8_t flags = Data[0];
    size_t cursor = 1;
    size_t remaining = (Size > 1) ? (Size - 1) : 0;

    // Choose a few common xml entity types (fall back to 0)
    const int type_table[] = {
        XML_INTERNAL_GENERAL_ENTITY,
        XML_EXTERNAL_GENERAL_PARSED_ENTITY,
        XML_EXTERNAL_GENERAL_UNPARSED_ENTITY,
        XML_INTERNAL_PARAMETER_ENTITY,
        XML_EXTERNAL_PARAMETER_ENTITY,
        XML_INTERNAL_PREDEFINED_ENTITY,
        0, 0
    };
    int type_idx = flags & 0x7;
    int type = type_table[type_idx % (sizeof(type_table)/sizeof(type_table[0]))];

    int extSubset = (flags >> 3) & 0x1;
    int set_out = (flags >> 4) & 0x1;

    // Split remaining bytes into up to 4 roughly-equal parts for name, publicId, systemId, content
    const uint8_t *p = Data + cursor;
    size_t rem = remaining;
    size_t part_count = 4;
    size_t base_part = (rem / part_count);
    size_t extra = rem % part_count;

    char *parts[4] = { NULL, NULL, NULL, NULL };
    for (size_t i = 0; i < part_count; ++i) {
        size_t part_len = base_part + (i < extra ? 1 : 0);
        if (part_len > 0) {
            parts[i] = make_string_from_data(p, part_len);
            p += part_len;
        } else {
            // create an empty string rather than NULL so name isn't NULL
            parts[i] = make_string_from_data((const uint8_t *)"", 0);
        }
    }

    // Ensure we have a valid document and a DTD (internal subset)
    xmlDocPtr doc = xmlNewDoc((const xmlChar *)"1.0");
    if (doc == NULL) goto cleanup;

    // Create an internal DTD. xmlNewDtd will attach a DTD (intSubset)
    xmlDtdPtr dtd = xmlNewDtd(doc, (const xmlChar *)"fuzzdtd", NULL, NULL);
    (void)dtd; // may be NULL on allocation failure, but xmlAddEntity checks for DTD presence

    // If caller requested extSubset but we only created intSubset, we will still call with extSubset=1.
    // xmlAddEntity will return XML_DTD_NO_DTD if the requested subset is not present - that's OK for fuzzing.

    xmlEntity *out_entity = NULL;
    xmlEntity **outp = set_out ? &out_entity : NULL;

    // Prepare xmlChar* arguments (cast from char*)
    const xmlChar *name = (const xmlChar *)parts[0];
    const xmlChar *publicId = (const xmlChar *)parts[1];
    const xmlChar *systemId = (const xmlChar *)parts[2];
    const xmlChar *content = (const xmlChar *)parts[3];

    // xmlAddEntity expects name != NULL and doc != NULL; we ensured name is non-NULL (maybe empty string)
    // Call the target function
    int res = xmlAddEntity((xmlDoc *)doc,
                           extSubset,
                           name,
                           type,
                           publicId,
                           systemId,
                           content,
                           outp);

    // Do NOT free out_entity: when xmlAddEntity succeeds it links the entity into the document's DTD
    // and the document owns it. xmlFreeDoc will free the DTD and its entities. Freeing out_entity here
    // causes a double-free / use-after-free. So we intentionally do not call xmlFreeEntity(out_entity).

    // Free the doc (which also frees attached DTD and many other structures)
    xmlFreeDoc(doc);

cleanup:
    for (int i = 0; i < 4; ++i) {
        if (parts[i]) {
            free(parts[i]);
            parts[i] = NULL;
        }
    }

    return 0;
}
