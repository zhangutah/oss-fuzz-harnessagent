
// Generate a fuzz driver based the given function signature in CPP language.
// The following function fuzzes
//     int handle__pubrel(struct mosquitto * mosq);
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Fuzz driver for: int handle__pubrel(struct mosquitto * mosq);
// Builds a minimal mosquitto instance, feeds the fuzzer input as the incoming packet payload,
// and calls handle__pubrel. Designed to be compiled as C++ (for libFuzzer).

extern "C" {
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
}
#include <assert.h>

// Include project headers. These paths are taken from the repository layout.
// If your build system sets include directories differently, adjust accordingly.
extern "C" {
#include "/src/mosquitto/lib/read_handle.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/lib/packet_mosq.h"
#include "/src/mosquitto/include/mosquitto.h"
/* Include broker internal header so we can access/initialize `db` for broker builds */
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

#ifdef __cplusplus
extern "C" {
#endif

// Fuzzer entry point required by libFuzzer.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Ensure db.config is initialized in broker builds to avoid dereferencing NULL.
    // Make this idempotent so repeated fuzzer invocations don't leak repeatedly.
#ifdef WITH_BROKER
    static int __db_config_inited = 0;
    if(!__db_config_inited){
        if(db.config == NULL){
            db.config = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
            if(db.config){
                /* Set to a large positive limit so packet__queue_append won't drop or access other fields. */
                db.config->max_queued_messages = 1000000;
            }
        } else {
            /* If already present, ensure max_queued_messages is non-zero to avoid checks causing unexpected behavior. */
            if(db.config->max_queued_messages == 0){
                db.config->max_queued_messages = 1000000;
            }
        }
        __db_config_inited = 1;
    }
#endif

    // Allocate and zero-initialize a mosquitto struct.
    struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!mosq) return 0;

    // Ensure ID is non-NULL for logging macros that might be used.
    mosq->id = (char *)calloc(5, 1);
    if(mosq->id) {
        memcpy(mosq->id, "fuzz", 4);
    }

    // Initialize protocol to something other than mqtt31 so the code path that checks
    // the fixed header value will be used. Use mqtt311 or mqtt5; either is fine.
    mosq->protocol = mosq_p_mqtt311;

#if defined(WITH_THREADING) && !defined(WITH_BROKER)
    // Initialize the mutexes that may be used by mosquitto__get_state.
    pthread_mutexattr_t mattr;
    if(pthread_mutexattr_init(&mattr) == 0){
        pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&mosq->state_mutex, &mattr);
        pthread_mutexattr_destroy(&mattr);
    } else {
        // If we can't init attributes, try direct init.
        pthread_mutex_init(&mosq->state_mutex, NULL);
    }
#endif
    // Directly set the state (the getter will read it under the mutex if present).
    mosq->state = mosq_cs_active;

    // Prepare the incoming packet structure to point at the fuzzer data.
    // Use a small non-null allocation if Size==0 to avoid any potential NULL dereferences.
    if(Size == 0){
        // allocate a single byte to represent an empty packet
        mosq->in_packet.payload = (uint8_t *)malloc(1);
        mosq->in_packet.remaining_length = 0;
    }else{
        mosq->in_packet.payload = (uint8_t *)malloc(Size);
        if(mosq->in_packet.payload == NULL){
            // allocation failed
            free(mosq->id);
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
            pthread_mutex_destroy(&mosq->state_mutex);
#endif
            free(mosq);
            return 0;
        }
        memcpy(mosq->in_packet.payload, Data, Size);
        mosq->in_packet.remaining_length = (uint32_t)Size;
    }
    mosq->in_packet.pos = 0;

    // The code checks the fixed header for CMD_PUBREL and the low nibble being 0x02.
    // Set the packet command accordingly so we exercise the PUBREL handling logic.
    mosq->in_packet.command = (uint8_t)(CMD_PUBREL | 0x02U);

    // Call the target function. It will parse the packet payload that we've set.
    // We don't inspect the return code here; the fuzzing engine monitors for crashes, leaks, etc.
    (void)handle__pubrel(mosq);

    // Clean up any queued outgoing packets to avoid leaks from packet__alloc/packet__queue.
    packet__cleanup_all(mosq);

    // Clean up.
    if(mosq->in_packet.payload){
        free(mosq->in_packet.payload);
    }
    if(mosq->id){
        free(mosq->id);
    }
#if defined(WITH_THREADING) && !defined(WITH_BROKER)
    pthread_mutex_destroy(&mosq->state_mutex);
#endif
    free(mosq);

    return 0;
}

#ifdef __cplusplus
}
#endif
