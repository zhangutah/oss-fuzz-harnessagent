#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cassert>

extern "C" {
    // Include project headers by absolute path (as found in the workspace).
    // These provide the declaration of send__publish and struct mosquitto.
    #include "/src/mosquitto/lib/send_mosq.h"
    // Include broker internal header to get full definitions of mosquitto__config,
    // mosquitto__security_options and mosquitto_db (not just forward declarations).
    #include "/src/mosquitto/src/mosquitto_broker_internal.h"
    // Include packet cleanup function to avoid leaking queued packets between fuzz runs.
    #include "/src/mosquitto/lib/packet_mosq.h"
}

// Ensure we can reference the global db declared in broker internals.
extern "C" {
    extern struct mosquitto_db db;
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Simple deterministic parsing of input bytes into parameters.
    size_t pos = 0;

    // mid (uint16_t) - use 2 bytes if available
    uint16_t mid = 0;
    if(pos + 2 <= Size){
        mid = (uint16_t)(Data[pos]) | ((uint16_t)(Data[pos+1]) << 8);
        pos += 2;
    }else if(pos < Size){
        mid = Data[pos];
        pos = Size;
    }

    // qos (0..2)
    uint8_t qos = 0;
    if(pos < Size){
        qos = Data[pos] % 3;
        pos++;
    }

    // retain (bool)
    bool retain = false;
    if(pos < Size){
        retain = (Data[pos] & 0x1) != 0;
        pos++;
    }

    // dup (bool)
    bool dup = false;
    if(pos < Size){
        dup = (Data[pos] & 0x1) != 0;
        pos++;
    }

    // subscription_identifier (uint32_t)
    uint32_t subscription_identifier = 0;
    if(pos + 4 <= Size){
        subscription_identifier = (uint32_t)Data[pos] | ((uint32_t)Data[pos+1] << 8) | ((uint32_t)Data[pos+2] << 16) | ((uint32_t)Data[pos+3] << 24);
        pos += 4;
    }else{
        // take whatever remains
        uint32_t shift = 0;
        while(pos < Size){
            subscription_identifier |= ((uint32_t)Data[pos]) << shift;
            shift += 8;
            pos++;
        }
    }

    // expiry_interval (uint32_t)
    uint32_t expiry_interval = 0;
    // If there are at least 4 bytes left, consume them, else leave 0
    if(pos + 4 <= Size){
        expiry_interval = (uint32_t)Data[pos] | ((uint32_t)Data[pos+1] << 8) | ((uint32_t)Data[pos+2] << 16) | ((uint32_t)Data[pos+3] << 24);
        pos += 4;
    }else{
        expiry_interval = 0;
    }

    // Topic: pick a small slice for use as a C string. Must be null-terminated.
    // Ensure we have at least 1 byte for topic; if not, create a short topic.
    const size_t MAX_TOPIC_LEN = 256;
    char *topic_cstr = nullptr;
    if(pos < Size){
        size_t remaining = Size - pos;
        size_t tlen = remaining;
        if(tlen > MAX_TOPIC_LEN - 1) tlen = MAX_TOPIC_LEN - 1;
        // Ensure topic length is at least 1
        if(tlen == 0) tlen = 1;
        topic_cstr = (char *)malloc(tlen + 1);
        if(!topic_cstr) return 0;
        memcpy(topic_cstr, Data + pos, tlen);
        topic_cstr[tlen] = '\0';
        pos += tlen;
    }else{
        // fallback topic
        const char *fallback = "fuzz/topic";
        topic_cstr = (char *)malloc(strlen(fallback) + 1);
        if(!topic_cstr) return 0;
        strcpy(topic_cstr, fallback);
    }

    // Payload: remaining bytes (may be zero-length)
    const void *payload_ptr = nullptr;
    uint32_t payloadlen = 0;
    uint8_t *payload_buf = nullptr;
    if(pos < Size){
        payloadlen = (uint32_t)(Size - pos);
        // Limit payload size to something reasonable to avoid huge allocations during fuzzing
        const uint32_t MAX_PAYLOAD = 65536;
        if(payloadlen > MAX_PAYLOAD) payloadlen = MAX_PAYLOAD;
        payload_buf = (uint8_t *)malloc(payloadlen);
        if(!payload_buf){
            free(topic_cstr);
            return 0;
        }
        memcpy(payload_buf, Data + pos, payloadlen);
        payload_ptr = payload_buf;
    }else{
        payload_ptr = NULL;
        payloadlen = 0;
    }

    // Prepare a minimal mosquitto structure.
    struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!mosq){
        free(topic_cstr);
        if(payload_buf) free(payload_buf);
        return 0;
    }

    // Initialize just the fields used by send__publish / send__real_publish:
    // - sock must not equal INVALID_SOCKET (net__is_connected checks this)
    // - retain_available used in send__publish
    // - protocol used in send__real_publish
    // - id used in logging (can be NULL, but set a small string to be safe)
    // - listener/bridge default to NULL to avoid some codepaths
    // - out_packet / other fields left zero-initialized

    // Set sock to a valid non-invalid value. INVALID_SOCKET is typically -1, so set to 1.
    #ifdef WIN32
        mosq->sock = (mosq_sock_t)1;
    #else
        mosq->sock = (mosq_sock_t)1;
    #endif

    mosq->retain_available = true;
    // Choose an MQTT protocol that is commonly used and reduces branching (mqtt311).
    mosq->protocol = mosq_p_mqtt311;
    // Set a short id string
    const char *idstr = "fuzzer";
    mosq->id = (char *)malloc(strlen(idstr) + 1);
    if(mosq->id){
        strcpy(mosq->id, idstr);
    }

    // Prevent huge packet allocations by imposing a reasonable maximum packet size for this test mosquitto.
    // This stops send__real_publish from attempting very large allocations during fuzzing.
    mosq->maximum_packet_size = 1024;

    // Keep listener and bridge NULL (calloc already set them to NULL), safe defaults.

    // Initialize global db.config and minimal security options to avoid NULL deref in plugin__handle_message_out.
    // plugin__handle_message_out does: plugin__handle_message_single(db.config->security_options.plugin_callbacks.message_out, ...)
    // so db.config must be non-NULL and its security_options/plugin_callbacks must be valid (they can contain NULL callback pointers).
    static struct mosquitto__config static_cfg;
    static struct mosquitto__security_options static_sec;
    // Zero-initialize both
    memset(&static_cfg, 0, sizeof(static_cfg));
    memset(&static_sec, 0, sizeof(static_sec));
    // Assign security options by value (mosquitto__config contains a struct, not a pointer).
    static_cfg.security_options = static_sec;
    // Disable per-listener settings to avoid second branch in plugin__handle_message_out
    static_cfg.per_listener_settings = false;

    // Assign to global db
    db.config = &static_cfg;

    // Call the target function. store_props is set to NULL for simplicity.
    // We pass parsed parameters derived from the input buffer.
    // Wrap call with volatile to attempt to prevent the compiler optimizing it away.
    volatile int rc = send__publish(mosq, mid, topic_cstr, payloadlen, payload_ptr, qos, retain, dup, subscription_identifier, NULL, expiry_interval);
    (void)rc;

    // Cleanup queued packets to avoid leaking memory across fuzzing iterations.
    // send__publish -> send__real_publish may call packet__alloc and packet__queue,
    // which stores the packet on mosq->out_packet. Free any queued packets now.
    packet__cleanup_all(mosq);

    // Cleanup
    if(mosq->id) free(mosq->id);
    free(mosq);
    free(topic_cstr);
    if(payload_buf) free(payload_buf);

    return 0;
}