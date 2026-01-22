#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <string>
#include <pthread.h>

// Project headers (absolute paths discovered with analysis tools).
// Wrap C headers in extern "C" to ensure correct linkage when compiling as C++.
extern "C" {
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/lib/send_mosq.h"
#include "/src/mosquitto/lib/packet_mosq.h" /* Added to access packet__cleanup_all */
#include "/src/mosquitto/libcommon/property_common.h"

// Some platforms may require these for INVALID_SOCKET, etc.
#include "/src/mosquitto/include/mosquitto/defs.h"

// Broker internals to access `db` and struct mosquitto__config.
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Allocate and zero-initialize a mosquitto context.
    struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!mosq) return 0;

    // Default to no socket / not connected.
#ifdef INVALID_SOCKET
    mosq->sock = INVALID_SOCKET;
#else
    // Fallback: use -1 (common on POSIX)
    mosq->sock = (mosq_sock_t)-1;
#endif

    size_t pos = 0;

    // Choose protocol from first byte (if available) to increase coverage.
    if(Size > 0){
        uint8_t proto_choice = Data[0] % 3;
        if(proto_choice == 0){
            mosq->protocol = mosq_p_mqtt5;
        }else if(proto_choice == 1){
            mosq->protocol = mosq_p_mqtt311;
        }else{
            mosq->protocol = mosq_p_mqtt31;
        }
        pos = 1;
    }else{
        mosq->protocol = mosq_p_mqtt311;
    }

    // Parse keepalive (2 bytes) if available, otherwise use default 60.
    uint16_t keepalive = 60;
    if(Size >= pos + 2){
        keepalive = (uint16_t)((Data[pos] << 8) | Data[pos+1]);
        pos += 2;
    }

    // Parse clean_session flag (1 byte) if available.
    bool clean_session = false;
    if(Size > pos){
        clean_session = (Data[pos] & 0x1) ? true : false;
        pos++;
    }

    // Ensure broker global db.config is non-NULL to avoid dereferencing NULL in packet__queue_append.
    // Allocate a minimal config if not already present.
#ifdef WITH_BROKER
    if(db.config == NULL){
        db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
        if(db.config){
            // Set fields used by packet__queue_append and related code to safe defaults.
            db.config->max_queued_messages = 0; // zero avoids entering drop-queue branch.
            db.config->max_queued_bytes = 0;
            db.config->max_packet_size = 0;
            db.config->message_size_limit = 0;
            db.config->max_inflight_messages = 0;
        }
    }
#endif

    // Helper lambda: create a NUL-terminated string from Data starting at pos, with at most maxlen bytes.
    auto make_string = [&](size_t maxlen) -> char* {
        if(pos >= Size) return nullptr;
        size_t available = Size - pos;
        size_t len = available < maxlen ? available : maxlen;
        // Avoid zero-length allocations: require at least 1 char for empty string representation.
        if(len == 0) return nullptr;
        char *s = (char *)malloc(len + 1);
        if(!s) return nullptr;
        memcpy(s, Data + pos, len);
        s[len] = '\0';
        pos += len;
        return s;
    };

    // Create id, username, password from subsequent bytes (bounded sizes).
    // Keep lengths small to avoid excessive allocations.
    char *id = make_string(32);
    char *username = make_string(32);
    char *password = make_string(32);

    // Assign to mosq fields. The send__connect implementation reads id/username/password.
    mosq->id = id ? id : NULL;
    mosq->username = username ? username : NULL;
    mosq->password = password ? password : NULL;

    // The send__connect code may check will and other fields. We keep will NULL for simplicity.
    mosq->will = NULL;

    // Set some other mosq fields to reasonable defaults to avoid UB.
    mosq->retain_available = false;
    mosq->keepalive = keepalive;
#ifndef WITH_BROKER
    // These fields only exist in non-broker builds.
    mosq->threaded = mosq_ts_none;
    mosq->callback_depth = 0;
#endif
    mosq->out_packet = NULL;
    mosq->out_packet_count = 0;
    mosq->out_packet_bytes = 0;
    mosq->maximum_packet_size = 0; // allow any size

    // Initialize mutex if present in this build's mosquitto struct to avoid locking an uninitialized mutex.
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
    // The mutex type is pthread_mutex_t in the codebase; initialize with default attributes.
    pthread_mutexattr_t attr;
    if(pthread_mutexattr_init(&attr) == 0){
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_NORMAL);
        pthread_mutex_init(&mosq->out_packet_mutex, &attr);
        pthread_mutexattr_destroy(&attr);
    }else{
        // Fall back to default init if attribute init failed.
        pthread_mutex_init(&mosq->out_packet_mutex, NULL);
    }
#endif

    // No properties constructed here; pass NULL. send__connect handles null properties.
    const mosquitto_property *properties = NULL;

    // Call the target function with fuzzed parameters.
    // We ignore the returned error code; this is just for coverage/fuzzing.
    (void)send__connect(mosq, keepalive, clean_session, properties);

    // Cleanup queued packets to avoid leaking memory across fuzzer iterations.
    // packet__cleanup_all frees any packets appended to mosq->out_packet.
    packet__cleanup_all(mosq);

    // Cleanup allocated strings and mosq object.
    if(mosq->id){ free(mosq->id); mosq->id = NULL; }
    if(mosq->username){ free(mosq->username); mosq->username = NULL; }
    if(mosq->password){ free(mosq->password); mosq->password = NULL; }

#if defined(WITH_THREADING) && !defined(WITH_BROKER)
    // Destroy mutex if we initialized it.
    pthread_mutex_destroy(&mosq->out_packet_mutex);
#endif

    free(mosq);

#ifdef WITH_BROKER
    // Optionally free the minimal db.config we allocated earlier. Make sure we don't free
    // a config that belonged to the application - in this harness it's safe because we allocated it.
    if(db.config){
        free(db.config);
        db.config = NULL;
    }
#endif

    return 0;
}
