// Fixed harness: uses the project's mosquitto_loop_write implementation.
// The file includes /src/mosquitto/lib/loop.c so that the real function
// (and its static helpers) are used. We provide a stubbed packet__write
// which reads from the fuzz buffer to drive behavior.

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <climits>

extern "C" {

// Forward-declare mosquitto_property so our stub callback signature matches
// the real project's declaration (avoids unknown type / ambiguous call errors).
typedef struct mqtt5__property mosquitto_property;

// Expose fuzz buffer globally so our stubbed helper (packet__write) can consume bytes deterministically.
static const uint8_t *g_fuzz_data = nullptr;
static size_t g_fuzz_size = 0;
static size_t g_fuzz_pos = 0;

// Helper to safely consume one byte from the fuzz buffer. If no data remains, returns 0.
static inline uint8_t consume_byte_or_zero() {
    if(!g_fuzz_data || g_fuzz_pos >= g_fuzz_size) return 0;
    return g_fuzz_data[g_fuzz_pos++];
}

// Stubbed packet__write used to drive mosquitto_loop_write paths.
// Real implementation writes to sockets and depends on full project internals;
// for fuzzing we drive behavior from the fuzz input:
// - If the consumed byte == 0 : return 0 (success).
// - If == 1 : set errno = EAGAIN, return 0 (would block).
// - If == 2 : set errno = COMPAT_EWOULDBLOCK, return 0 (would block).
// - If == 3 : return -1 (an arbitrary non-zero rc).
// - Otherwise: return the consumed byte value (non-zero).
// Make this static to avoid multiple-definition against the project's packet__write.
static int packet__write(struct mosquitto *mosq) {
    (void)mosq;
    uint8_t v = consume_byte_or_zero();
    if(v == 0) {
        return 0;
    } else if(v == 1) {
        errno = EAGAIN;
        return 0;
    } else if(v == 2) {
#ifndef COMPAT_EWOULDBLOCK
#define COMPAT_EWOULDBLOCK EWOULDBLOCK
#endif
        errno = COMPAT_EWOULDBLOCK;
        return 0;
    } else if(v == 3) {
        // arbitrary non-zero rc
        return -1;
    } else {
        // return some non-zero rc to trigger mosquitto__loop_rc_handle path
        return (int)v;
    }
}

// Provide minimal stubs for functions referenced by loop.c that may be missing
// from the link in the fuzzing build. Keep implementations minimal and safe.

int socks5__read(struct mosquitto *mosq) {
    (void)mosq;
    return 0; // MOSQ_ERR_SUCCESS
}

int http_c__read(struct mosquitto *mosq) {
    (void)mosq;
    return 0; // MOSQ_ERR_SUCCESS
}

void callback__on_disconnect(struct mosquitto *mosq, int rc, const mosquitto_property *props) {
    (void)mosq; (void)rc; (void)props;
    // no-op
}

bool mosquitto__get_request_disconnect(struct mosquitto *mosq) {
    (void)mosq;
    return false;
}

int mosquitto_reconnect(struct mosquitto *mosq) {
    (void)mosq;
    return 0; // MOSQ_ERR_SUCCESS
}

// fuzz_packet_read lifecycle helpers (some harness files expect these symbols).
int fuzz_packet_read_init(struct mosquitto *context) {
    (void)context;
    return 0;
}
void fuzz_packet_read_cleanup(struct mosquitto *context) {
    (void)context;
}

// Ensure we compile the non-broker variant so struct mosquitto contains
// sockpairR/sockpairW which loop.c expects. This avoids missing-member errors
// when including the real loop.c in this harness translation unit.
#ifdef WITH_BROKER
#undef WITH_BROKER
#endif

// Now include the real implementation of mosquitto_loop_write from the project.
// This ensures we fuzz the actual target function instead of a fake reimplementation.
#include "/src/mosquitto/lib/loop.c"

} // extern "C"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Expose fuzz buffer to mocked helpers.
    g_fuzz_data = Data;
    g_fuzz_size = Size;
    g_fuzz_pos = 0;

    // Allocate a minimal mosquitto instance (the real functions don't inspect it in our stub).
    struct mosquitto *mosq = (struct mosquitto*)malloc(sizeof(struct mosquitto));
    if(!mosq) return 0;
    memset(mosq, 0, sizeof(*mosq));

    // Derive max_packets from the first two bytes of the input if available.
    // Interpreted as a signed 16-bit integer to allow negative values (to test MOSQ_ERR_INVAL).
    int max_packets = 1; // default when not enough data present
    if(Size >= 2) {
        int16_t raw = (int16_t)((Data[0] << 8) | Data[1]);
        max_packets = (int)raw;
    } else if(Size == 1) {
        int8_t raw = (int8_t)Data[0];
        max_packets = (int)raw;
    } else {
        max_packets = 1;
    }

    // Cap extremes to avoid pathological runs in the harness.
    const int CAP = 2000;
    if(max_packets > CAP) max_packets = CAP;
    if(max_packets < -CAP) max_packets = -CAP;

    // Call the real function from the project.
    (void)mosquitto_loop_write(mosq, max_packets);

    // Clean up.
    free(mosq);

    // Reset fuzz buffer pointers.
    g_fuzz_data = nullptr;
    g_fuzz_size = 0;
    g_fuzz_pos = 0;

    return 0;
}
