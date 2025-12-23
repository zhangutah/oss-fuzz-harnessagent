#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/valid.h>   /* xmlDumpElementTable, xmlFreeElementTable declarations */
#include <libxml/tree.h>    /* xmlBuffer, xmlBufferCreate, xmlBufferFree, xmlNewDocNode, xmlFreeNode */
#include <libxml/hash.h>    /* xmlHashCreate, xmlHashAddEntry, xmlHashFree */
#include <libxml/xmlsave.h> /* xmlSaveToBuffer, xmlSaveFinish (used internally by xmlDumpElementTable) */
#include <libxml/parser.h>  /* xmlInitParser - safe to call before using libxml APIs */

/* Deallocator wrapper compatible with xmlHashFree:
 * xmlHashDeallocator has signature: void (*)(void *payload, const xmlChar *name)
 *
 * We free payloads created as xml nodes via xmlFreeNode.
 * Do NOT free the key/name here: xmlHashFree will free the key itself when appropriate.
 */
static void fuzz_hash_deallocator(void *payload, const xmlChar *name) {
    if (payload) {
        /* payloads are xmlNodePtr created with xmlNewDocNode */
        xmlFreeNode((xmlNodePtr)payload);
    }
    /* Do not free 'name' here -- xmlHashFree will free entry->key when needed. */
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == NULL || Size == 0)
        return 0;

    /* Initialize libxml parser (idempotent) */
    xmlInitParser();

    /* Create a buffer for xmlDumpElementTable to write into */
    xmlBufferPtr buf = xmlBufferCreate();
    if (buf == NULL)
        return 0;

    /* Create an xml hash table to act as xmlElementTable */
    /* Limit initial size to avoid huge allocations */
    int table_size = 32;
    xmlElementTable *table = (xmlElementTable *)xmlHashCreate(table_size);
    if (table == NULL) {
        xmlBufferFree(buf);
        return 0;
    }

    /* Parse input bytes to create several entries in the hash table.
     * Simple format:
     * - Use bytes iteratively: for each entry, take a name_len (1..max_name),
     *   then name bytes, then payload_len (1..max_payload), then payload bytes.
     * - Stop when no more bytes or reached max entries.
     *
     * We will create a real xml node (xmlNewDocNode) per entry and use it
     * as the payload. That prevents xmlSaveTree from reading arbitrary
     * heap memory and avoids the heap-buffer-overflow.
     */
    size_t pos = 0;
    const size_t max_entries = 64;
    const size_t max_name = 64;
    const size_t max_payload = 256;
    size_t entries = 0;

    while (pos < Size && entries < max_entries) {
        /* Name length */
        size_t remaining = Size - pos;
        uint8_t b = Data[pos++];
        size_t name_len = (b & 0x0F) + 1; /* 1..16 */
        if (name_len > max_name) name_len = max_name;
        if (name_len > remaining) {
            /* Not enough bytes left for name */
            break;
        }

        /* Create name as an xmlChar* (using libxml allocator) */
        const xmlChar *name_tmp = NULL;
        if (pos + name_len > Size) break;
        name_tmp = xmlStrndup((const xmlChar *)(Data + pos), (int)name_len);
        if (name_tmp == NULL) break;
        pos += name_len;

        /* Determine payload length */
        if (pos >= Size) {
            /* No bytes left to decide payload; create a small node with no content */
            xmlNodePtr node = xmlNewDocNode(NULL, NULL, name_tmp, NULL);
            if (node != NULL) {
                /* Insert into hash. xmlHashAddEntry will copy the key internally. */
                int res = xmlHashAddEntry((xmlHashTable *)table, name_tmp, (void *)node);
                /* xmlHashAddEntry returns 0 on success, non-zero on error.
                 * Free the node only if insertion failed.
                 */
                if (res != 0) {
                    /* insertion failed: free node */
                    xmlFreeNode(node);
                }
            }
            /* free the temporary name we allocated */
            xmlFree((void *)name_tmp);
            entries++;
            break;
        }

        /* We have at least one byte for payload-length */
        uint8_t pb = Data[pos++];
        size_t payload_len = (pb & 0xFF) % (max_payload) + 1;

        /* Compute how many bytes remain for payload */
        size_t avail = (pos <= Size) ? (Size - pos) : 0;

        const xmlChar *content_tmp = NULL;
        if (avail == 0) {
            /* No bytes available for payload content: create node with NULL content */
            payload_len = 0;
            content_tmp = NULL;
        } else {
            if (payload_len > avail) payload_len = avail;
            /* Create content string for the node (may contain embedded zeros but we limit copy) */
            content_tmp = xmlStrndup((const xmlChar *)(Data + pos), (int)payload_len);
            if (content_tmp == NULL) {
                /* cleanup name and exit */
                xmlFree((void *)name_tmp);
                break;
            }
        }

        /* Advance pos by payload bytes actually used */
        size_t copy_len = payload_len;
        if (pos + copy_len > Size) {
            copy_len = (Size - pos);
        }
        pos += copy_len;

        /* Create an xml node that will be used as payload. xmlNewDocNode duplicates name/content internally. */
        xmlNodePtr node = xmlNewDocNode(NULL, NULL, name_tmp, content_tmp);
        if (content_tmp) xmlFree((void *)content_tmp); /* free temporary content copy */

        if (node == NULL) {
            xmlFree((void *)name_tmp);
            break;
        }

        /* Add entry to the hash table. xmlHashAddEntry copies the key into its own storage. */
        int added = xmlHashAddEntry((xmlHashTable *)table, name_tmp, (void *)node);
        /* We've created name_tmp with xmlStrndup, but xmlHashAddEntry will create its own copy for the entry.
         * Free our temporary copy unconditionally.
         */
        xmlFree((void *)name_tmp);

        /* xmlHashAddEntry returns 0 on success, non-zero on error.
         * If insertion failed free the node we created and stop processing.
         */
        if (added != 0) {
            /* insertion failed; free the node we created */
            xmlFreeNode(node);
            break;
        }

        entries++;
    }

    /* Call the function under test */
    /* xmlDumpElementTable writes to buf based on the contents of table */
    xmlDumpElementTable(buf, (xmlElementTable *)table);

    /* Optionally, we could inspect or free the buffer contents. */
    /* xmlBufferFree will free internal data. */
    xmlBufferFree(buf);

    /* Free the hash table and allocated entries using our deallocator wrapper */
    xmlHashFree((xmlHashTable *)table, (xmlHashDeallocator)fuzz_hash_deallocator);

    /* No explicit xmlCleanupParser() here; fuzzers typically avoid global cleanup each iteration. */
    return 0;
}
