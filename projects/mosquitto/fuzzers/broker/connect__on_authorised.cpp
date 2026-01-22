#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <new>

// Include project headers (absolute paths found by analysis).
// If your build system places headers in different locations, adjust these includes accordingly.
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if(!Data || Size == 0) return 0;

    // Helper to consume bytes from Data safely.
    size_t pos = 0;
    auto take_byte = [&]() -> uint8_t {
        if(pos >= Size) return 0;
        return Data[pos++];
    };
    auto take_bytes = [&](uint8_t *dst, size_t len) {
        if(len == 0) return;
        size_t avail = (pos < Size) ? (Size - pos) : 0;
        size_t tocopy = (len <= avail) ? len : avail;
        if(tocopy) {
            memcpy(dst, Data + pos, tocopy);
            pos += tocopy;
        }
        if(tocopy < len) {
            memset(dst + tocopy, 0, len - tocopy);
        }
    };

    // Create a zero-initialized mosquitto context using mosquitto allocator so
    // that later cleanup (which uses mosquitto_FREE/mosquitto_free) won't
    // trigger an alloc/free mismatch under memory tracking.
    struct mosquitto *context = (struct mosquitto *)mosquitto_calloc(1, sizeof(struct mosquitto));
    if(!context) return 0;

    // Track allocations we perform so we can avoid double-free (we'll let
    // context__cleanup handle freeing of most fields).
    char *allocated_id = nullptr;
    char *allocated_username = nullptr;
    struct mosquitto__listener *allocated_listener = nullptr;

    // 1) Client ID: derive a length from the first byte, limit to reasonable max (128).
    uint8_t id_len = take_byte() % 128;
    if(id_len == 0) id_len = 1; // ensure non-empty id so strlen(context->id) is safe
    char *idbuf = (char *)mosquitto_malloc(id_len + 1);
    if(!idbuf){
        // cleanup using mosquitto allocator
        mosquitto_free(context);
        return 0;
    }
    take_bytes((uint8_t*)idbuf, id_len);
    idbuf[id_len] = '\0';
    context->id = idbuf;
    allocated_id = idbuf;

    // 2) Username (optional)
    uint8_t uname_len = take_byte() % 64;
    if(uname_len) {
        char *ubuf = (char *)mosquitto_malloc(uname_len + 1);
        if(ubuf){
            take_bytes((uint8_t*)ubuf, uname_len);
            ubuf[uname_len] = '\0';
            context->username = ubuf;
            allocated_username = ubuf;
        }
    }

    // 3) Protocol selection: use a safe known enum value present in code.
    //    Prefer MQTT5 if available, otherwise fallback to small integer.
#ifdef mosq_p_mqtt5
    context->protocol = (enum mosquitto__protocol)(mosq_p_mqtt5);
#else
    // If the enum isn't available at compile time for some reason, set numeric 5.
    context->protocol = (enum mosquitto__protocol)5;
#endif

    // 4) keepalive and flags
    context->keepalive = (uint16_t)(take_byte()); // small keepalive value
    context->clean_start = (take_byte() & 1) ? true : false;

    // 5) listener: allocate and fill minimal fields used by connect__on_authorised
    struct mosquitto__listener *listener = (struct mosquitto__listener *)mosquitto_calloc(1, sizeof(struct mosquitto__listener));
    if(!listener){
        // cleanup
        if(allocated_username) mosquitto_free(allocated_username);
        if(allocated_id) mosquitto_free(allocated_id);
        mosquitto_free(context);
        return 0;
    }
    listener->max_qos = (uint8_t)(take_byte() & 0x03); // keep it small (0-3)
    listener->max_topic_alias = (uint16_t)(take_byte()); // small
    listener->mount_point = NULL;
    listener->use_username_as_clientid = false;
    context->listener = listener;
    allocated_listener = listener;

    // 6) Set will to NULL (common case)
    context->will = NULL;

    // 7) Initialize msgs_in/out data so references are safe if used.
    //    These are embedded in struct mosquitto; zeroed by calloc already.

    // 8) Ensure db.config exists and has conservative values.
    if(db.config == NULL) {
        db.config = (struct mosquitto__config *)mosquitto_calloc(1, sizeof(struct mosquitto__config));
        if(db.config) {
            // Set limits so connect__on_authorised typically doesn't bail out early:
            db.config->global_max_clients = 0; // disable global client limit check
            db.config->connection_messages = false;
            db.config->max_keepalive = 0; // 0 means no enforced maximum in their check
            db.config->message_size_limit = 0; // no message size limit
            db.config->packet_buffer_size = 1024; // safe default used by context__init
            db.config->max_inflight_messages = 10; // reasonable default
        }
    } else {
        // If a config already exists in the test environment, try to set safe values
        db.config->global_max_clients = 0;
        db.config->connection_messages = false;
        db.config->max_keepalive = 0;
        db.config->message_size_limit = 0;
        if(db.config->packet_buffer_size == 0) db.config->packet_buffer_size = 1024;
        if(db.config->max_inflight_messages == 0) db.config->max_inflight_messages = 10;
    }

    // 9) Ensure the contexts_by_id list is null (no existing clients) for determinism.
    db.contexts_by_id = NULL;

    // 10) Optionally set address/remote_port for log messages; not required but safe.
    context->address = NULL;
    context->remote_port = 0;
    context->is_bridge = false;
#if defined(__cplusplus)
    // assigned_id may or may not exist, setting via name only if present
#endif
    // If assigned_id exists in struct, set it; otherwise compiled-away.
    // Use C-style member access (compiles only if member exists as the headers used).
#ifdef assigned_id
    context->assigned_id = false;
#endif

    int rc = 0;
    try {
        rc = connect__on_authorised(context, NULL, 0);
        (void)rc;
    } catch(...) {
        // swallow exceptions to avoid aborting the fuzzer harness.
    }

    // Important: remove the context from the global db hash so repeated runs don't leak memory.
    // This avoids the global hash growing across fuzzer iterations and OOMing.
    context__remove_from_by_id(context);

    // Cleanup: use broker-provided cleanup so allocated packets and properties are freed.
    // context__cleanup(context, true) will free context and owned resources using mosquitto_FREE.
    context__cleanup(context, true);

    // Free listener we allocated if it wasn't freed by the broker cleanup.
    // context__cleanup does not free listener objects, so free if still present.
    if(allocated_listener){
        mosquitto_free(allocated_listener);
        allocated_listener = nullptr;
    }

    // Do not free db.config here; leaving it allocated is fine for the persistent fuzzer process.

    return 0;
}