// Fuzz driver for handle__unsubscribe
// Generated fuzz entry point: LLVMFuzzerTestOneInput
//
// Notes:
// - This driver constructs a minimal struct mosquitto instance and fills its
//   in_packet payload with the fuzzer input bytes. It sets fields used by
//   handle__unsubscribe so the function can parse the packet and exercise
//   code paths. The driver does not attempt to fully populate the entire
//   mosquitto state; it aims to be lightweight while being safe to call.

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "mosquitto_broker_internal.h"
#include "mosquitto/mqtt_protocol.h"
#include "packet_mosq.h"

int handle__unsubscribe(struct mosquitto *context);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0){
        return 0;
    }

    // Allocate and zero a mosquitto context.
    struct mosquitto *ctx = (struct mosquitto*)calloc(1, sizeof(struct mosquitto));
    if(!ctx) return 0;

    // Set minimal required fields.
    ctx->state = mosq_cs_active;
    // Use MQTT v3.1.1 so property parsing for v5 is not triggered.
    ctx->protocol = mosq_p_mqtt311;

    // Provide an id string used by logging calls.
    const char *id_text = "fuzzer";
    ctx->id = (char *)malloc(strlen(id_text) + 1);
    if(ctx->id){
        strcpy(ctx->id, id_text);
    }

    // Ensure global db.config is allocated and initialised so functions like
    // mosquitto_acl_check don't dereference a NULL pointer.
    // db is declared in mosquitto_broker_internal.h as: extern struct mosquitto_db db;
    bool we_allocated_config = false;
    if(db.config == NULL){
        db.config = (struct mosquitto__config*)calloc(1, sizeof(struct mosquitto__config));
        if(!db.config){
            free(ctx->id);
            free(ctx);
            return 0;
        }
        we_allocated_config = true;
    }
    // Set sane defaults used by code paths:
    db.config->per_listener_settings = false;
    // security_options is part of the config struct and calloc'ed -> zeroed.
    // This leaves plugin callbacks NULL which causes plugin branches to be skipped.

    // Initialize in_packet so parsing functions can read from it.
    // Copy fuzzer input into a new buffer used as packet payload.
    struct mosquitto__packet_in *pin = &ctx->in_packet;
    memset(pin, 0, sizeof(*pin));

    // Allocate payload buffer and copy Data.
    uint8_t *buf = (uint8_t *)malloc(Size);
    if(!buf){
        // cleanup
        if(we_allocated_config){
            free(db.config);
            db.config = NULL;
        }
        free(ctx->id);
        free(ctx);
        return 0;
    }
    memcpy(buf, Data, Size);

    pin->payload = buf;
    pin->remaining_length = (uint32_t)Size;
    pin->pos = 0;
    // Set command to an UNSUBSCRIBE with fixed header flags (0xA0 | 0x02)
    pin->command = (uint8_t)(CMD_UNSUBSCRIBE | 2);

    // Call the target function. It will parse the payload from pin->payload.
    // We ignore the return value; the goal is to exercise code paths safely.
    (void)handle__unsubscribe(ctx);

    // Clean up outgoing packets queued by the code under test to avoid leaks.
    // send__unsuback may allocate an outgoing packet via packet__alloc, which is
    // then queued. Remove and free any such packets.
    packet__cleanup_all(ctx);

    // NOTE: packet__cleanup_all() calls packet__cleanup(&mosq->in_packet), which
    // frees in_packet.payload (the buffer 'buf' we allocated above). Do NOT free
    // buf again here or it will cause a double-free. The buffer has already been freed.

    // Free db.config we allocated above.
    if(we_allocated_config){
        free(db.config);
        db.config = NULL;
    }

    free(ctx->id);
    free(ctx);

    return 0;
}
