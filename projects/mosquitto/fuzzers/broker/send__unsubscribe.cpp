
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <string>
#include <cstdlib>
#include <algorithm>
#include <pthread.h>

extern "C" {
#include "/src/mosquitto/lib/send_mosq.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
/* For db and config definitions (broker internals) */
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
/* For packet cleanup function declaration */
#include "/src/mosquitto/lib/packet_mosq.h"
}

/* Ensure C++ sees the extern db symbol */
extern "C" {
extern struct mosquitto_db db;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if(!Data || Size == 0) {
        return 0;
    }

    // Simple PRNG over the provided bytes so we can deterministically consume them.
    size_t pos = 0;
    auto next_byte = [&](uint8_t fallback = 0) -> uint8_t {
        if(pos < Size) {
            return Data[pos++];
        }
        // If we run out, return fallback (and continue returning it).
        return fallback;
    };

    // Determine topic_count from first byte (0..7). We ensure the topic pointer passed is non-null
    // even when topic_count == 0 by allocating a vector with at least 1 element.
    uint8_t raw_count = next_byte(0);
    int topic_count = raw_count % 8; // limit to 0..7 to keep allocations small
    int vec_size = std::max(1, topic_count);

    std::vector<char*> topics(vec_size, nullptr);
    std::vector<size_t> allocated_lengths(vec_size, 0);

    // Build topic strings from remaining bytes. Cap each topic to a small length (0..127).
    for(int i = 0; i < topic_count; i++){
        uint8_t len_byte = next_byte(1);
        size_t tlen = 1 + (len_byte % 64); // topics 1..64 bytes long
        // allocate +1 for null terminator
        char *buf = (char*)malloc(tlen + 1);
        if(!buf){
            // allocation failed; fallback to an empty string stored in a static buffer
            static char empty_str[] = "";
            topics[i] = empty_str;
            allocated_lengths[i] = 0;
            continue;
        }
        for(size_t j = 0; j < tlen; j++){
            uint8_t b = next_byte(0x20); // printable-ish default
            // make printable ASCII range [32,126] to avoid embedded NULs
            char c = (char)(32 + (b % 95));
            buf[j] = c;
        }
        buf[tlen] = '\0';
        topics[i] = buf;
        allocated_lengths[i] = tlen + 1;
    }

    // If topic_count == 0 we must still pass a non-null pointer (send__unsubscribe asserts topic != NULL).
    // topics.data() is non-null because vec_size >= 1.
    // For the extra (unused) element, ensure it's a valid C string.
    if(topic_count == 0){
        // Provide a short static string to satisfy assert and any potential logging.
        static char default_topic[] = "fuzz";
        topics[0] = default_topic;
    }

    // Create a minimal mosquitto struct. Zero-initialize to reduce surprises.
    struct mosquitto *mosq = (struct mosquitto*)calloc(1, sizeof(struct mosquitto));
    if(!mosq){
        // cleanup allocated topics
        for(int i=0;i<topic_count;i++){
            if(allocated_lengths[i]) free(topics[i]);
        }
        return 0;
    }

    // Ensure broker DB config exists so packet__queue_append can safely read db.config->max_queued_messages.
    // In the broker build the global 'db' is defined elsewhere; we just allocate and assign db.config if needed.
    if(db.config == NULL){
        db.config = (struct mosquitto__config*)calloc(1, sizeof(struct mosquitto__config));
        if(db.config){
            db.config->max_queued_messages = 0; // 0 means 'no limit' in our use; avoids drop-path.
        }
    }

    // Note: some mosquitto builds include pthread mutex members inside struct mosquitto.
    // This build does not expose those members, so we avoid initializing/destroying them here.

    // Fill only the fields used by send__unsubscribe and packet queuing:
    // - protocol: used to determine whether to write properties and compute remaining length
    // - id: used in logging; set to a small string
    // - maximum_packet_size: leave as 0 (unused path)
    // - last_mid could be used by mid generator; zero is fine
    mosq->protocol = mosq_p_mqtt311; // default to MQTT 3.1.1; code checks for mosq_p_mqtt5 explicitly
    // If the fuzzer provides another byte indicating MQTT5, set it:
    uint8_t proto_choice = next_byte(0);
    if((proto_choice & 1) && sizeof(mosq->protocol) > 0){ // simple entropy: 50% chance
        mosq->protocol = mosq_p_mqtt5;
    }
    const char *client_id = "fuzzer";
    mosq->id = (char*)malloc(strlen(client_id) + 1);
    if(mosq->id){
        strcpy(mosq->id, client_id);
    }

    mosq->maximum_packet_size = 0;
    mosq->last_mid = 0;

    // Initialize out_packet bookkeeping so packet__queue_append can safely manipulate them.
    mosq->out_packet = NULL;
    mosq->out_packet_last = NULL;
    mosq->out_packet_count = 0;
    mosq->out_packet_bytes = 0;
    #ifdef WITH_BROKER
    mosq->is_dropping = false;
    #endif

    // Provide a place for mid (optional). Use local variable.
    int mid = 0;

    // Call the target function. properties set to NULL for simplicity.
    // The topics pointer must be of type char *const *const, and topics.data() provides that.
    (void)send__unsubscribe(mosq, &mid, topic_count, (char *const *const)topics.data(), NULL);

    // Cleanup queued packets to avoid leaking memory tracked by mosquitto_malloc.
    // Use the no_locks variant so we don't rely on mutex members being present/initialized.
    packet__cleanup_all_no_locks(mosq);

    // Cleanup topic buffers
    for(int i=0;i<topic_count;i++){
        if(allocated_lengths[i]) free(topics[i]);
    }
    if(mosq->id) free(mosq->id);

    // We did not initialize/destroy any pthread mutex members because they may not exist in this build.
    free(mosq);

    // Optionally free db.config if we allocated it here. We can't determine ownership reliably; avoid freeing
    // so we don't interfere with other tests. Leak is acceptable in fuzz harness short runs.

    return 0;
}