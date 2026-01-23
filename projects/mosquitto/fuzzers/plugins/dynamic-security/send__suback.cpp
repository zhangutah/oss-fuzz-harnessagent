// Fixed harness for fuzzing send__suback
// Adjusted to avoid large allocations driven by untrusted payload length.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <ctime>

extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"

/* Forward-declare memory / allocation helpers used by the broker so we can call
 * them from this C++ harness. These are defined in libcommon/memory_common.c
 * and are available in the broker build. */
void mosquitto_memory_set_limit(size_t lim);
void *mosquitto_calloc(size_t nmemb, size_t size);
char *mosquitto_strdup(const char *s);
void mosquitto_free(void *mem);

/* Ensure packet cleanup function is visible to this C++ file.
 * packet__cleanup_all is declared in lib/packet_mosq.h, but to be robust
 * (and avoid any conditional-inclusion surprises), forward-declare it here
 * with C linkage so the harness can call it. */
void packet__cleanup_all(struct mosquitto *mosq);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0){
        return 0;
    }

    /* Set a conservative memory limit for mosquitto's tracked allocator so the
     * target cannot allocate unbounded memory and exhaust the fuzzer process.
     * Adjust this as needed; keep it well below libFuzzer's process limit. */
    const size_t MOSQ_MEM_LIMIT = 16 * 1024 * 1024; // 16 MiB
    mosquitto_memory_set_limit(MOSQ_MEM_LIMIT);

    // Allocate and zero a mosquitto context using the broker allocator.
    struct mosquitto *ctx = (struct mosquitto *)mosquitto_calloc(1, sizeof(struct mosquitto));
    if(!ctx){
        return 0;
    }

    // Provide a stable, short, null-terminated id to avoid dereference/read-of-uninitialized memory.
    const char *static_id = "fuzz-client";
    ctx->id = mosquitto_strdup(static_id);
    if(!ctx->id){
        mosquitto_free(ctx);
        return 0;
    }

    // Choose a protocol value that is NOT mosq_p_mqtt5 so the MQTT v5 property handling path is skipped.
    ctx->protocol = (enum mosquitto__protocol)0;

    // Ensure the global broker DB config is valid to avoid dereferencing a NULL pointer
    // inside packet__queue_append (which references db.config->max_queued_messages).
    static struct mosquitto__config fuzz_db_config;
    memset(&fuzz_db_config, 0, sizeof(fuzz_db_config));
    fuzz_db_config.max_queued_messages = 0;
    db.config = &fuzz_db_config;
    db.now_s = (time_t)time(NULL);

    // Derive mid and payload.
    uint16_t mid = 0;
    const void *payload = NULL;
    uint32_t payloadlen = 0;

    // Cap payloadlen to prevent large allocations in send__suback.
    const uint32_t MAX_ACCEPTED_PAYLOAD = 4096; // 4 KiB cap

    if(Size >= 2){
        mid = (uint16_t)((Data[0] << 8) | Data[1]);

        size_t raw_payload_len = Size - 2;
        if(raw_payload_len > (size_t)MAX_ACCEPTED_PAYLOAD){
            payloadlen = MAX_ACCEPTED_PAYLOAD;
        }else{
            payloadlen = (uint32_t)raw_payload_len;
        }
        payload = (const void *)(Data + 2);
    }else{
        if(Size == 1){
            mid = (uint16_t)(Data[0]);
        }
        payload = NULL;
        payloadlen = 0;
    }

    (void)send__suback(ctx, mid, payloadlen, payload);

    // Clean up any queued packets allocated by send__suback/packet__alloc.
    // This prevents leaks when the harness returns.
    packet__cleanup_all(ctx);

    // Cleanup using broker free so memory accounting is consistent.
    mosquitto_free(ctx->id);
    mosquitto_free(ctx);

    return 0;
}
