#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" {
// Include the ACL header that declares acl_file__check and related structs.
#include "/src/mosquitto/src/acl_file.h"
// Include broker/event definitions for mosquitto_evt_acl_check etc.
#include "/src/mosquitto/include/mosquitto/broker.h"
}

// Provide weak/stub implementations for a handful of broker helper functions that
// acl_file__check uses. Marked weak so the project's real implementations will
// override them if linked.

extern "C" __attribute__((weak))
const char *mosquitto_client_id(const struct mosquitto *client)
{
    // We expect the pointer to actually point to a small fake struct allocated below.
    if(!client) return NULL;
    // Interpret the pointer as having a first member 'id' (const char *).
    const char * const *p = (const char * const *)client;
    return *p;
}

extern "C" __attribute__((weak))
const char *mosquitto_client_username(const struct mosquitto *client)
{
    // We expect the pointer to actually point to a small fake struct:
    // layout: [0] = id pointer, [1] = username pointer
    if(!client) return NULL;
    const char * const *p = (const char * const *)client;
    return p[1];
}

extern "C" __attribute__((weak))
int mosquitto_topic_matches_sub(const char *sub, const char *topic, bool *result)
{
    if(!sub || !topic || !result) return 1; // mimic MOSQ_ERR_INVAL
    // Simple substring-based heuristic match to avoid complex logic.
    *result = (strstr(topic, sub) != NULL) || (strcmp(sub, topic) == 0);
    return 0;
}

extern "C" __attribute__((weak))
int mosquitto_topic_matches_sub_with_pattern(const char *sub, const char *topic, const char *clientid, const char *username, bool *result)
{
    if(!sub || !topic || !result) return 1;
    // We do not implement the full pattern semantics here.
    // As a simple approximation, treat it same as the no-pattern match.
    *result = (strstr(topic, sub) != NULL) || (strcmp(sub, topic) == 0);
    return 0;
}

extern "C" __attribute__((weak))
void mosquitto_log_printf(int level, const char *fmt, ...)
{
    // No-op logging for fuzz harness.
    (void)level;
    (void)fmt;
}

// The fuzzer entry point:
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // We will split the input into three parts:
    // - topic (must be non-empty)
    // - client id (may be empty -> treated as NULL)
    // - username (may be empty -> treated as NULL)
    //
    // Also use first byte low bit to decide whether to create an acl_patterns entry
    // so we can exercise both pattern and non-pattern code paths.

    size_t min_topic_len = 1;
    if(Size < min_topic_len) return 0;

    // Determine partition sizes.
    // Give roughly 1/3 to topic, remainder split between clientid/username.
    size_t tlen = Size / 3;
    if(tlen == 0) tlen = 1;
    size_t remain = Size - tlen;
    size_t clen = remain / 2;
    size_t ulen = remain - clen;

    // Ensure topic non-empty
    if(tlen == 0) { tlen = 1; if(clen > 0) --clen; else if(ulen > 0) --ulen; }

    // Pointers into Data
    const uint8_t *p = Data;
    const char *topic_str = nullptr;
    char *topic_buf = nullptr;
    const char *clientid_str = nullptr;
    char *clientid_buf = nullptr;
    const char *username_str = nullptr;
    char *username_buf = nullptr;

    // Copy topic
    topic_buf = (char *)malloc(tlen + 1);
    if(!topic_buf) return 0;
    memcpy(topic_buf, p, tlen);
    topic_buf[tlen] = '\0';
    topic_str = topic_buf;
    p += tlen;

    // Copy client id (if length > 0)
    if(clen > 0){
        clientid_buf = (char *)malloc(clen + 1);
        if(!clientid_buf){ free(topic_buf); return 0; }
        memcpy(clientid_buf, p, clen);
        clientid_buf[clen] = '\0';
        clientid_str = clientid_buf;
    }else{
        clientid_str = NULL;
    }
    p += clen;

    // Copy username (if length > 0)
    if(ulen > 0){
        username_buf = (char *)malloc(ulen + 1);
        if(!username_buf){ free(topic_buf); free(clientid_buf); return 0; }
        memcpy(username_buf, p, ulen);
        username_buf[ulen] = '\0';
        username_str = username_buf;
    }else{
        username_str = NULL;
    }

    // Build a minimal fake client structure. Our weak mosquitto_client_id/username
    // stub expects the first two pointer-sized fields to be id and username.
    // We'll allocate two pointers and set them appropriately.
    void *client_mem = malloc(sizeof(void*) * 2);
    if(!client_mem){
        free(topic_buf); free(clientid_buf); free(username_buf);
        return 0;
    }
    const char **client_fields = (const char **)client_mem;
    client_fields[0] = clientid_str;   // id
    client_fields[1] = username_str;   // username

    // Prepare the mosquitto_evt_acl_check structure.
    struct mosquitto_evt_acl_check ed;
    memset(&ed, 0, sizeof(ed));
    ed.client = (struct mosquitto *)client_mem;
    ed.topic = topic_str;
    // Use a byte from the input to populate access flags. Ensure it is within a byte.
    uint8_t access_byte = Data[0];
    ed.access = (int)access_byte;

    // To increase coverage and avoid trivial early-return branches, flip a bit
    // in the access flags so that both code paths can be exercised.
    ed.access ^= 0x10;

    // Create acl_file_data to pass as userdata.
    struct acl_file_data data;
    memset(&data, 0, sizeof(data));
    data.acl_file = NULL;
    data.acl_users = NULL;
    data.acl_anon.acl = NULL;
    data.acl_patterns = NULL;

    // Decide whether to create a single acl_patterns entry (so pattern handling runs).
    // Use low bit of Data[0] to decide.
    if((Data[0] & 1) && clientid_str){
        // allocate single acl__entry and attach to data.acl_patterns
        struct acl__entry *entry = (struct acl__entry *)malloc(sizeof(struct acl__entry));
        if(entry){
            // Make a simple topic for the ACL pattern - reuse the topic_str we already made
            // (this will test topic matching logic).
            entry->topic = strdup(topic_str ? topic_str : "");
            entry->access = (ed.access & 0xFF); // give it some access bits
            entry->ucount = 0;
            entry->ccount = 0;
            entry->next = NULL;
            entry->prev = NULL;
            data.acl_patterns = entry;
        }
    } else {
        // Leave patterns NULL; this will exercise the non-pattern code path.
        data.acl_patterns = NULL;
    }

    // Call the target function under test.
    // Use event value MOSQ_EVT_ACL_CHECK (value doesn't matter because function UNUSED(event))
    int ret = acl_file__check(MOSQ_EVT_ACL_CHECK, (void *)&ed, (void *)&data);
    (void)ret; // ignore the result for fuzzing

    // Clean up allocated memory
    if(data.acl_patterns){
        if(data.acl_patterns->topic) free(data.acl_patterns->topic);
        free(data.acl_patterns);
    }
    free(client_mem);
    free(topic_buf);
    if(clientid_buf) free(clientid_buf);
    if(username_buf) free(username_buf);

    return 0;
}