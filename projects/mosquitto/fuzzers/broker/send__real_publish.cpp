// Fuzz driver for send__real_publish
// Generated to call:
// int send__real_publish(struct mosquitto * mosq, uint16_t mid, const char * topic,
//                        uint32_t payloadlen, const void * payload, uint8_t qos,
//                        _Bool retain, _Bool dup, uint32_t subscription_identifier,
//                        const mosquitto_property * store_props, uint32_t expiry_interval);

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <algorithm>

#ifdef __cplusplus
extern "C" {
#endif

// Project headers (absolute paths discovered in repository).
// These may be adjusted by the build system; keep absolute paths as discovered.
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/lib/send_mosq.h"
#include "/src/mosquitto/libcommon/property_common.h"
// For broker global db and config type.
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
// Packet helpers (cleanup functions)
#include "/src/mosquitto/lib/packet_mosq.h"

#ifdef __cplusplus
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if(!Data || Size == 0) return 0;

    // Use a simple cursor to read bytes from Data
    size_t pos = 0;
    auto read_u8 = [&](uint8_t &out) -> bool {
        if(pos + 1 > Size) return false;
        out = Data[pos];
        pos += 1;
        return true;
    };
    auto read_u16 = [&](uint16_t &out) -> bool {
        if(pos + 2 > Size) return false;
        out = (uint16_t)Data[pos] | ((uint16_t)Data[pos+1] << 8);
        pos += 2;
        return true;
    };
    auto read_u32 = [&](uint32_t &out) -> bool {
        if(pos + 4 > Size) return false;
        out = (uint32_t)Data[pos] | ((uint32_t)Data[pos+1] << 8) | ((uint32_t)Data[pos+2] << 16) | ((uint32_t)Data[pos+3] << 24);
        pos += 4;
        return true;
    };

    // Parse basic scalar fields from input (with safe defaults)
    uint8_t qos = 0;
    uint8_t flags = 0;
    uint16_t mid = 0;
    uint32_t subscription_identifier = 0;
    uint32_t expiry_interval = 0;

    read_u8(qos); // qos raw
    // Limit qos to [0,2] as MQTT requires
    qos = qos % 3;

    read_u8(flags); // use low bits for retain/dup
    bool retain = (flags & 0x1) != 0;
    bool dup = (flags & 0x2) != 0;

    // message id
    if(!read_u16(mid)) mid = 0;

    // subscription identifier and expiry interval
    if(!read_u32(subscription_identifier)) subscription_identifier = 0;
    if(!read_u32(expiry_interval)) expiry_interval = 0;

    // Next byte determines topic length (cap to something reasonable)
    size_t topic_len = 0;
    if(pos < Size) {
        uint8_t tlen = Data[pos++];
        // Bound topic length by remaining bytes and a cap
        size_t remain = Size - pos;
        size_t cap = std::min<size_t>(remain, 2048);
        topic_len = std::min<size_t>(tlen, cap);
    }

    // Extract topic string
    std::string topic;
    if(topic_len > 0 && pos + topic_len <= Size) {
        topic.assign(reinterpret_cast<const char*>(Data + pos), topic_len);
        pos += topic_len;
        // Ensure topic is valid C string (null-terminated for API calls)
        // If topic contains nulls, send__real_publish handles length via strlen(topic),
        // so keep as-is but ensure there is a trailing null in the buffer we'll pass.
    }

    // Remaining bytes are payload (or empty)
    size_t payload_len = 0;
    const void *payload_buf = nullptr;
    uint8_t *local_payload = nullptr;
    if(pos < Size) {
        size_t remain = Size - pos;
        // Cap payload length to avoid huge allocations
        size_t cap = std::min<size_t>(remain, 64 * 1024);
        payload_len = cap;
        local_payload = (uint8_t *)malloc(payload_len ? payload_len : 1);
        if(local_payload == nullptr) {
            return 0;
        }
        memcpy(local_payload, Data + pos, payload_len);
        payload_buf = local_payload;
        pos += payload_len;
    } else {
        // no payload
        payload_len = 0;
        payload_buf = nullptr;
    }

    // Prepare a minimal mosquitto struct.
    // The real struct is defined in mosquitto_internal.h which we included above.
    // We zero-initialize and then set a few fields used by send__real_publish and packet__* functions.
    struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!mosq) {
        free(local_payload);
        return 0;
    }

    // Set fields to safe defaults.
    // maximum_packet_size == 0 disables oversize checks (packet__check_oversize returns success).
    mosq->maximum_packet_size = 0;

    // Choose a protocol that exercises reasonable code path.
    // Use MQTT 3.1.1 (mosq_p_mqtt311) by default to avoid MQTT5 property handling unless the fuzzer decides to set expiry or subscription id.
    mosq->protocol = mosq_p_mqtt311;

    // Provide an id for logging code paths.
    const char *id_str = "fuzzer-client";
    mosq->id = (char *)malloc(strlen(id_str) + 1);
    if(mosq->id) strcpy(mosq->id, id_str);

    // Do not set fields that only exist in the non-broker build (callback_depth, threaded, sockpairW, wsi).
    // Those fields are conditionally present in struct mosquitto; setting them unconditionally causes compile errors
    // when WITH_BROKER is defined (as is the case for broker fuzz targets).

    // Set transport to TCP (use the enum value defined in mosquitto_internal.h).
    mosq->transport = mosq_t_tcp;

    // If we have a topic string, ensure we have a C string with a terminating NUL
    char *topic_cstr = nullptr;
    if(!topic.empty()) {
        topic_cstr = (char*)malloc(topic.size() + 1);
        if(topic_cstr) {
            memcpy(topic_cstr, topic.data(), topic.size());
            topic_cstr[topic.size()] = '\0';
        }
    } else {
        // pass NULL topic (allowed)
        topic_cstr = nullptr;
    }

    // For MQTT v5 flows, the function may examine store_props; pass NULL for now.
    const mosquitto_property *store_props = nullptr;

    // Choose expiry_interval and subscription_identifier values derived earlier.
    // If the fuzzer supplied a topic and we want to exercise MQTT5 properties, we could set mosq->protocol = mosq_p_mqtt5,
    // but by default we keep it at MQTT 3.1.1 to reduce complexity.
    uint32_t expiry = expiry_interval;
    uint32_t sub_id = subscription_identifier;

    // --- Broker-specific global initialisation to avoid NULL derefs in send/packet code ---
    // Ensure db.config is non-NULL. packet__queue_append reads db.config->max_queued_messages.
    if(db.config == NULL){
        db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
        if(db.config){
            // Set conservative default: no queue limit enforcement here.
           db.config->max_queued_messages = 0;
        }
    }

    // Ensure out packet bookkeeping fields are sane
    mosq->out_packet = NULL;
    // Many builds have out_packet_last as part of the struct (broker or non-broker variants).
    // Set to NULL where present:
#ifdef __cplusplus
// need to keep preprocessor within C++ raw block; the file is C++ so use the same guard pattern.
#endif
#ifdef WITH_BROKER
    mosq->out_packet_last = NULL;
#else
    mosq->out_packet_last = NULL;
#endif
    mosq->out_packet_count = 0;
    mosq->out_packet_bytes = 0;

    // Set sockets to INVALID so packet__queue won't try to write to them.
#ifdef INVALID_SOCKET
    mosq->sock = INVALID_SOCKET;
#  ifndef WITH_BROKER
    mosq->sockpairR = INVALID_SOCKET;
    mosq->sockpairW = INVALID_SOCKET;
#  endif
#else
    mosq->sock = (mosq_sock_t)-1;
#  ifndef WITH_BROKER
    mosq->sockpairR = (mosq_sock_t)-1;
    mosq->sockpairW = (mosq_sock_t)-1;
#  endif
#endif

    // Initialize mutexes if the build defines them. COMPAT_pthread_mutex_init is available in the codebase.
#if defined(WITH_THREADING) || defined(HAVE_PTHREAD_H)
    // COMPAT_pthread_mutex_init is a compatibility wrapper provided by the project.
    // If the struct contains these mutexes, initialize them to avoid undefined behaviour when locking.
#  if defined(HAVE_PTHREAD_H) || defined(WITH_THREADING)
    COMPAT_pthread_mutex_init(&mosq->out_packet_mutex, NULL);
    COMPAT_pthread_mutex_init(&mosq->msgtime_mutex, NULL);
#  endif
#endif

    // --- End broker-specific initialisation ---

    // Call the target function. Wrap in a try/catch to avoid C++ exceptions interfering (function is C).
    int rc = 0;
    // send__real_publish signature:
    // int send__real_publish(struct mosquitto *mosq, uint16_t mid, const char *topic,
    //                        uint32_t payloadlen, const void *payload, uint8_t qos,
    //                        bool retain, bool dup, uint32_t subscription_identifier,
    //                        const mosquitto_property *store_props, uint32_t expiry_interval);
    rc = send__real_publish(mosq,
                            mid,
                            topic_cstr,
                            (uint32_t)payload_len,
                            payload_buf,
                            qos,
                            (bool)retain,
                            (bool)dup,
                            sub_id,
                            store_props,
                            expiry);

    // Cleanup
    // Free any queued packets and their payloads to avoid leaking memory across fuzz iterations.
    if(mosq) {
        // packet__cleanup_all will free packet memory using mosquitto_free and reset out_packet fields.
        packet__cleanup_all(mosq);
    }
    if(topic_cstr) free(topic_cstr);
    if(mosq->id) free(mosq->id);
    free(mosq);
    free(local_payload);

    // Return 0 as per libFuzzer contract
    (void)rc;
    return 0;
}