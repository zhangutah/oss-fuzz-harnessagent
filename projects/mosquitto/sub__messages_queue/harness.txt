#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>

// mosquitto internals are C; ensure C linkage for their declarations.
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

// Some builds may require C linkage for the fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Parse small header from Data:
    // Byte 0 -> qos (0..2)
    // Byte 1 -> retain flag (0 or 1)
    // Remaining bytes -> source_id and topic (split evenly)
    uint8_t qos = Data[0] % 3; // MQTT QoS 0..2
    int retain = 0;
    if(Size > 1) retain = Data[1] & 1;

    const uint8_t *payload_ptr = Data + 2;
    size_t payload_size = (Size > 2) ? (Size - 2) : 0;

    // Split remaining bytes into source_id and topic.
    size_t source_len = payload_size / 2;
    size_t topic_len = payload_size - source_len;

    std::string source_id;
    std::string topic;

    if(source_len > 0){
        source_id.assign(reinterpret_cast<const char*>(payload_ptr), source_len);
    }
    if(topic_len > 0){
        topic.assign(reinterpret_cast<const char*>(payload_ptr + source_len), topic_len);
    }

    // Ensure topic is a non-null C string (tokeniser expects a C string pointer).
    // If empty, give it a simple default topic to avoid pathological errors.
    if(topic.empty()){
        topic = "fuzz/topic";
    }

    // Allocate and populate a minimal mosquitto__base_msg structure.
    struct mosquitto__base_msg *bm = (struct mosquitto__base_msg *)calloc(1, sizeof(struct mosquitto__base_msg));
    if(!bm) return 0;

    // Zero-initialised via calloc; fill in fields used by the code path:
    // - data.payloadlen and data.payload (payload bytes)
    // - data.qos and data.retain
    // - ref_count to a sane starting value
    size_t msg_payload_len = topic_len; // reuse part of input as payload length
    if(msg_payload_len > 0){
        void *p = malloc(msg_payload_len);
        if(p){
            memcpy(p, reinterpret_cast<const void*>(payload_ptr + source_len), msg_payload_len);
            bm->data.payload = p;
            bm->data.payloadlen = static_cast<uint32_t>(msg_payload_len);
        }else{
            bm->data.payload = NULL;
            bm->data.payloadlen = 0;
        }
    }else{
        bm->data.payload = NULL;
        bm->data.payloadlen = 0;
    }

    bm->data.qos = qos;
    bm->data.retain = (retain != 0);
    bm->ref_count = 1;

    // IMPORTANT CHANGE:
    // Prevent plugin_persist__handle_base_msg_add from attempting to access
    // global broker state (db.config) which is not initialised in this harness.
    // plugin_persist__handle_base_msg_add returns immediately if base_msg->stored
    // is true, so set stored = true to avoid the plugin callback and the crash.
    //
    // This avoids dereferencing NULL/invalid db.config in the fuzzer environment.
    bm->stored = true;

    // IMPORTANT: retain.c expects base_msg->data.topic to be a valid C string
    // when storing retained messages. If this is NULL, retain__store may
    // dereference it and crash. Set data.topic to a copy of the topic we pass
    // to sub__messages_queue. Also set source_id to a copy if present.
    const char *source_c = source_id.empty() ? NULL : source_id.c_str();
    const char *topic_c = topic.c_str();

    bm->data.topic = NULL;
    bm->data.source_id = NULL;
    if(topic_c){
        // strdup uses malloc, free with free() below.
        char *topic_dup = strdup(topic_c);
        if(topic_dup){
            bm->data.topic = topic_dup;
        }
    }
    if(source_c){
        char *src_dup = strdup(source_c);
        if(src_dup){
            bm->data.source_id = src_dup;
        }
    }
    bm->data.source_username = NULL;

    // Prepare pointer-to-pointer argument.
    struct mosquitto__base_msg *stored = bm;

    // Call the target function.
    // Note: source_id.c_str() may contain embedded NULs; sub__messages_queue expects C strings,
    // so we pass c_str() (which is NUL-terminated). If source_id is empty, pass NULL.

    // CAUTION: retain handling in the broker calls into plugin persistence code,
    // which expects the broker global state to be configured. The fuzzer harness
    // doesn't set up that state. To avoid crashes originating in plugin/persist
    // code (e.g. plugin_persist__handle_retain_msg_set), force 'retain' to 0
    // for the sub__messages_queue call and ensure our base_msg reflects that.
    retain = 0;
    bm->data.retain = false;

    // Call target function. It may modify 'stored' (or increment refcount).
    // We ignore the return value here; fuzzer is primarily interested in crashes, undefined behavior.
    (void)sub__messages_queue(source_c, topic_c, qos, retain, &stored);

    // Clean up:
    // stored may have been modified by sub__messages_queue. We free what we allocated if still present.
    // To be conservative, check the pointer and attempt to free the payload and strings if it's our allocation.
    if(stored){
        // If payload pointer is non-null and equals what we allocated, free it.
        if(bm->data.payload && stored->data.payload == bm->data.payload){
            free(bm->data.payload);
            stored->data.payload = NULL;
        }
        // If topic pointer equals our duplicated one, free it.
        if(bm->data.topic && stored->data.topic == bm->data.topic){
            free(bm->data.topic);
            stored->data.topic = NULL;
        }
        // If source_id pointer equals our duplicated one, free it.
        if(bm->data.source_id && stored->data.source_id == bm->data.source_id){
            free(bm->data.source_id);
            stored->data.source_id = NULL;
        }
        // Free the base_msg struct we allocated. Even if stored != bm, we still free our original to avoid leaks.
        free(bm);
    } else {
        // stored is NULL - still free our original allocation if any
        // Free payload/topic/source_id if they weren't already freed.
        if(bm->data.payload) free(bm->data.payload);
        if(bm->data.topic) free(bm->data.topic);
        if(bm->data.source_id) free(bm->data.source_id);
        free(bm);
    }

    return 0;
}
