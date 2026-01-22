#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <climits>

extern "C" {
#include "mosquitto_broker_internal.h"
}

// Use the project's single global db instance. Do not define it here to avoid
// duplicate-definition / ASAN ODR instrumentation symbol conflicts.
extern "C" struct mosquitto_db db;

// Ensure the C function has correct linkage for C++ compilation.
extern "C" bool db__ready_for_flight(struct mosquitto *context, enum mosquitto_msg_direction dir, int qos);

// Helper: safely consume bytes from Data[] for integer values.
static inline uint64_t read_u64(const uint8_t *data, size_t size, size_t &pos) {
    uint64_t v = 0;
    size_t to_read = (size - pos) >= 8 ? 8 : (size - pos);
    for(size_t i=0;i<to_read;i++){
        v |= (uint64_t)data[pos++] << (i*8);
    }
    // if insufficient bytes, advance pos to end (no-op)
    return v;
}
static inline uint32_t read_u32(const uint8_t *data, size_t size, size_t &pos) {
    uint32_t v = 0;
    size_t to_read = (size - pos) >= 4 ? 4 : (size - pos);
    for(size_t i=0;i<to_read;i++){
        v |= (uint32_t)data[pos++] << (i*8);
    }
    return v;
}
static inline uint16_t read_u16(const uint8_t *data, size_t size, size_t &pos) {
    uint16_t v = 0;
    size_t to_read = (size - pos) >= 2 ? 2 : (size - pos);
    for(size_t i=0;i<to_read;i++){
        v |= (uint16_t)data[pos++] << (i*8);
    }
    return v;
}
static inline int64_t read_s64(const uint8_t *data, size_t size, size_t &pos) {
    return (int64_t)read_u64(data, size, pos);
}
static inline int32_t read_s32(const uint8_t *data, size_t size, size_t &pos) {
    return (int32_t)read_u32(data, size, pos);
}

// The fuzzer entry point required by LLVM libFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Defensive: if no data, still exercise a few configurations.
    if(!Data || Size == 0) {
        // Minimal deterministic call
        struct mosquitto context;
        memset(&context, 0, sizeof(context));
        // Set reasonable defaults
        context.out_packet_count = 0;
        context.msgs_in.inflight_maximum = 1;
        context.msgs_in.inflight_bytes = 0;
        context.msgs_in.inflight_count = 0;
        context.msgs_in.inflight_bytes12 = 0;
        context.msgs_in.inflight_quota = 1;
        // Ensure db.config exists
        db.config = (struct mosquitto__config*)calloc(1, sizeof(struct mosquitto__config));
        if(db.config){
            db.config->max_inflight_bytes = 1024;
            db.config->max_queued_bytes = 1024;
            db.config->max_queued_messages = 10;
        }
        (void)db__ready_for_flight(&context, mosq_md_in, 0);
        free(db.config);
        db.config = nullptr;
        return 0;
    }

    // Use bytes from Data to initialize fields used by db__ready_for_flight.
    size_t pos = 0;

    // Determine direction (0=in, 1=out)
    uint8_t dir_byte = Data[pos++];
    enum mosquitto_msg_direction dir = (dir_byte & 1) ? mosq_md_out : mosq_md_in;

    // Determine qos (0,1,2)
    uint8_t qos_byte = (pos < Size) ? Data[pos++] : 0;
    int qos = qos_byte % 3;

    // Allocate and zero a context
    struct mosquitto context;
    memset(&context, 0, sizeof(context));

    // Fill context->out_packet_count (used when dir==out & qos==0)
    if(pos < Size){
        context.out_packet_count = (int)read_u32(Data, Size, pos) % 100000;
    }else{
        context.out_packet_count = 0;
    }

    // Initialize msgs_in and msgs_out fields (we'll fill both; function picks one)
    // For safety, zero both and then set fields from Data.
    memset(&context.msgs_in, 0, sizeof(context.msgs_in));
    memset(&context.msgs_out, 0, sizeof(context.msgs_out));

    // inflight_maximum (uint16_t in some places)
    uint16_t inflight_maximum = 0;
    if(pos < Size) inflight_maximum = read_u16(Data, Size, pos);
    context.msgs_in.inflight_maximum = (int)inflight_maximum;
    context.msgs_out.inflight_maximum = (int)inflight_maximum;

    // inflight_bytes (ssize_t)
    if(pos < Size) context.msgs_in.inflight_bytes = (ssize_t)read_s64(Data, Size, pos);
    if(pos < Size) context.msgs_out.inflight_bytes = (ssize_t)read_s64(Data, Size, pos);

    // inflight_count
    if(pos < Size) context.msgs_in.inflight_count = (int)read_u32(Data, Size, pos) % 100000;
    if(pos < Size) context.msgs_out.inflight_count = (int)read_u32(Data, Size, pos) % 100000;

    // inflight_bytes12
    if(pos < Size) context.msgs_in.inflight_bytes12 = (size_t)read_u64(Data, Size, pos);
    if(pos < Size) context.msgs_out.inflight_bytes12 = (size_t)read_u64(Data, Size, pos);

    // inflight_count12
    if(pos < Size) context.msgs_in.inflight_count12 = (int)read_u32(Data, Size, pos) % 100000;
    if(pos < Size) context.msgs_out.inflight_count12 = (int)read_u32(Data, Size, pos) % 100000;

    // inflight_quota
    if(pos < Size) context.msgs_in.inflight_quota = (int)read_s32(Data, Size, pos);
    if(pos < Size) context.msgs_out.inflight_quota = (int)read_s32(Data, Size, pos);

    // queued bytes/count (may be used indirectly in some configurations)
    if(pos < Size) context.msgs_in.queued_bytes = (ssize_t)read_s64(Data, Size, pos);
    if(pos < Size) context.msgs_in.queued_count = (int)read_u32(Data, Size, pos) % 100000;

    if(pos < Size) context.msgs_out.queued_bytes = (ssize_t)read_s64(Data, Size, pos);
    if(pos < Size) context.msgs_out.queued_count = (int)read_u32(Data, Size, pos) % 100000;

    // Prepare global db.config (allocate if not already)
    db.config = (struct mosquitto__config*)calloc(1, sizeof(struct mosquitto__config));
    if(!db.config){
        return 0;
    }

    // Populate db.config fields used by db__ready_for_flight
    // max_inflight_bytes, max_queued_bytes, max_queued_messages
    // We read these from Data (if available) to create variety.
    uint64_t tmp64 = 0;
    if(pos < Size) tmp64 = read_u64(Data, Size, pos);
    db.config->max_inflight_bytes = (size_t)(tmp64 % (UINT64_C(1) << 50)); // clamp to reasonable range

    if(pos < Size) tmp64 = read_u64(Data, Size, pos);
    db.config->max_queued_bytes = (size_t)(tmp64 % (UINT64_C(1) << 50));

    if(pos < Size) db.config->max_queued_messages = (int)(read_u32(Data, Size, pos) % 100000);
    else db.config->max_queued_messages = 0;

    // Some code paths check max_inflight_bytes == 0 or max_queued_bytes == 0, so allow zeros
    // Also set queue_qos0_messages flag possibly used elsewhere (not in this function but safe).
    if(pos < Size) db.config->queue_qos0_messages = (read_u32(Data, Size, pos) & 1) ? true : false;
    else db.config->queue_qos0_messages = false;

    // Call the function under test. It will read the populated context & db.config.
    // Try both in and out branches by using the chosen dir.
    // The return value is ignored; we only ensure the function runs without UB for these inputs.
    (void)db__ready_for_flight(&context, dir, qos);

    // Clean up
    free(db.config);
    db.config = nullptr;

    return 0;
}
