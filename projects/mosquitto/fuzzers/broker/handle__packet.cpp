#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
}

/*
 Fuzzer entry point
 This harness zero-initializes a struct mosquitto, sets minimal fields,
 ensures global `db.config` is a valid pointer to avoid dereferencing NULL
 in do_disconnect(), and sets the socket to INVALID_SOCKET so the code
 doesn't try to operate on socket/hash tables.
*/
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        // Still create context with a defined command (0).
    }

    // Allocate and zero a mosquitto context
    struct mosquitto *ctx = (struct mosquitto *)malloc(sizeof(struct mosquitto));
    if (!ctx) return 0;
    memset(ctx, 0, sizeof(struct mosquitto));

    // Ensure global db.config is valid to avoid NULL deref in do_disconnect().
    // Allocate it once per process.
    static bool db_config_inited = false;
    if (!db_config_inited) {
        struct mosquitto__config *cfg = (struct mosquitto__config *)calloc(1, sizeof(struct mosquitto__config));
        if (cfg) {
            // Use safe defaults.
            cfg->connection_messages = false;
            cfg->daemon = false;
            cfg->listener_count = 0;
            cfg->default_listener = NULL;
        }
        /* db is declared in the included header as: extern struct mosquitto_db db; */
        db.config = cfg;
        /* quiet/verbose are in db, not in mosquitto__config */
        db.quiet = true;
        db.verbose = false;
        db_config_inited = true;
    }

    // Initialize minimal fields used by handle__packet
    // Set the command nibble from input to exercise different branches.
    if (Size > 0) {
        ctx->in_packet.command = Data[0];
    } else {
        ctx->in_packet.command = 0;
    }

    // Prevent socket-related branches from running by marking socket invalid.
    ctx->sock = INVALID_SOCKET;

    // Ensure protocol is a safe default (zero) which typically != mosq_p_mqtt5.
    ctx->protocol = (enum mosquitto__protocol)0;

    // Call the target function under test.
    (void)handle__packet(ctx);

    // Keep db.config allocated for the process lifetime to avoid repeated alloc/free.
    // Clean up the context for this run.
    free(ctx);

    return 0;
}