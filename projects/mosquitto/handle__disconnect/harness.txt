// Fuzz harness for real project function: int handle__disconnect(struct mosquitto * context)
// This harness constructs a real struct mosquitto (from the project) and populates
// its in_packet with the fuzzer input, then calls the project's handle__disconnect.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <string.h> // for strdup on some toolchains

// Include project internal headers as C symbols, since the project is C.
extern "C" {
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

// Do NOT define `db` here if the project already provides it; that causes
// multiple-definition link errors (observed with ASan instrumentation).
// Instead, declare it as extern so we refer to the broker's global.
extern "C" {
extern struct mosquitto_db db;
}

// If CMD_DISCONNECT isn't available from included headers for some build setups,
// define it here as the standard MQTT DISCONNECT control packet (type 14 << 4).
#ifndef CMD_DISCONNECT
#define CMD_DISCONNECT 0xE0
#endif

// Fuzzer entry point required by libFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data) return 0;

    // Ensure db.config is present and initialised to sane defaults so
    // do_disconnect() and related functions don't dereference a null pointer.
    if(db.config == NULL){
        db.config = (struct mosquitto__config *)malloc(sizeof(struct mosquitto__config));
        if(db.config){
            std::memset(db.config, 0, sizeof(struct mosquitto__config));
            // Disable connection_messages to avoid code paths that log using possibly
            // uninitialised context fields. This keeps the harness minimal and safe.
            db.config->connection_messages = false;
        }
    }

    // Construct and zero-initialize the mosquitto context.
    struct mosquitto ctx_storage;
    std::memset(&ctx_storage, 0, sizeof(ctx_storage));
    struct mosquitto *ctx = &ctx_storage;

    // Set an id string the code can log/inspect.
    // The project expects char * id; allocate a small copy.
    const char *id_src = "fuzz-client";
    ctx->id = strdup(id_src);
    if(!ctx->id){
        // If strdup fails, still continue without id.
        ctx->id = nullptr;
    }

    // Prepare packet payload. The project's packet reading functions expect
    // a contiguous payload pointer and remaining_length.
    uint8_t *payload = nullptr;
    if(Size > 0){
        payload = (uint8_t *)malloc(Size);
        if(!payload){
            if(ctx->id) free((void*)ctx->id);
            // free db.config only if we allocated it here; we keep it for reuse across runs
            return 0;
        }
        std::memcpy(payload, Data, Size);
    }

    // Populate the in_packet (mosquitto__packet_in).
    // Note: struct field names follow lib/mosquitto_internal.h:
    //   uint8_t *payload;
    //   uint32_t remaining_length;
    //   uint32_t pos;
    //   uint8_t command;
    //
    ctx->in_packet.payload = payload;
    ctx->in_packet.remaining_length = (uint32_t)Size;
    ctx->in_packet.pos = 0;

    // Ensure this is treated as a DISCONNECT control packet (high nibble 0xE0).
    uint8_t low_nibble = 0x00;
    if(Size >= 1){
        low_nibble = (Data[0] & 0x0F);
    }
    ctx->in_packet.command = (uint8_t)((CMD_DISCONNECT & 0xF0) | (low_nibble & 0x0F));

    // Choose protocol variant based on input (to exercise different branches).
    // Use mosq_p_mqtt5 vs mosq_p_mqtt311 from the project's enum.
    if(Size >= 2){
        uint8_t v = Data[1];
        if((v & 0x01) == 0){
            ctx->protocol = mosq_p_mqtt5;
        }else{
            ctx->protocol = mosq_p_mqtt311;
        }
    }else{
        ctx->protocol = mosq_p_mqtt5;
    }

    // Call the real project function under test.
    // Surround call by try/catch to prevent C++ exceptions from escaping (project code is C).
    // (This is defensive; project code shouldn't throw.)
    int rc = 0;
    try {
        rc = handle__disconnect(ctx);
    } catch (...) {
        // ignore, but avoid aborting the fuzzer process.
    }

    // Cleanup
    if(payload) free(payload);
    if(ctx->id) free((void*)ctx->id);

    (void)rc; // suppress unused variable warning

    return 0;
}
