#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>

// Include the project's internal header and ensure C linkage for declarations
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

// Declare (do not define) the global 'db' with C linkage so the project's function can access it.
// Previously this file defined 'db' which caused multiple definition linker errors.
extern "C" {
extern struct mosquitto_db db;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    size_t idx = 0;
    auto read_u8 = [&](uint8_t &out)->bool {
        if(idx + 1 > Size) return false;
        out = Data[idx++];
        return true;
    };
    auto read_u16 = [&](uint16_t &out)->bool {
        if(idx + 2 > Size) return false;
        uint16_t v = 0;
        memcpy(&v, Data + idx, 2);
        idx += 2;
        out = v;
        return true;
    };
    auto read_u32 = [&](uint32_t &out)->bool {
        if(idx + 4 > Size) return false;
        uint32_t v = 0;
        memcpy(&v, Data + idx, 4);
        idx += 4;
        out = v;
        return true;
    };
    auto read_u64 = [&](uint64_t &out)->bool {
        if(idx + 8 > Size) return false;
        uint64_t v = 0;
        memcpy(&v, Data + idx, 8);
        idx += 8;
        out = v;
        return true;
    };

    // Prepare and attach a local config object to the global db
    static struct mosquitto__config cfg;
    // Zero-init to be safe
    memset(&cfg, 0, sizeof(cfg));
    db.config = &cfg;

    // Fill config fields from input where available, otherwise use Size-derived defaults
    uint64_t tmp64 = 0;
    uint32_t tmp32 = 0;
    uint16_t tmp16 = 0;
    uint8_t tmp8 = 0;

    if(read_u64(tmp64)){
        cfg.max_inflight_bytes = (long)tmp64;
    } else {
        cfg.max_inflight_bytes = (long)Size;
    }
    if(read_u32(tmp32)){
        cfg.max_queued_messages = (int)(tmp32 % 100000);
    } else {
        cfg.max_queued_messages = (int)(Size % 1000);
    }
    if(read_u64(tmp64)){
        cfg.max_queued_bytes = (long)tmp64;
    } else {
        cfg.max_queued_bytes = (long)(Size * 10);
    }
    if(read_u8(tmp8)){
        cfg.queue_qos0_messages = (tmp8 & 1) != 0;
    } else {
        cfg.queue_qos0_messages = ((Size & 1) != 0);
    }

    // Prepare msg_data using project's struct
    struct mosquitto_msg_data msg;
    memset(&msg, 0, sizeof(msg));
    if(read_u64(tmp64)){
        msg.queued_bytes12 = (long)tmp64;
    } else {
        msg.queued_bytes12 = (long)(Size * 2);
    }
    if(read_u32(tmp32)){
        msg.queued_count12 = (int)(tmp32 % 100000);
    } else {
        msg.queued_count12 = (int)(Size % 1000);
    }
    if(read_u16(tmp16)){
        msg.inflight_maximum = tmp16 % 65535;
    } else {
        msg.inflight_maximum = (uint16_t)(Size % 100);
    }

    // Prepare a mosquitto context. Zero-init entire struct to avoid UB from uninitialized fields.
    struct mosquitto ctx;
    memset(&ctx, 0, sizeof(ctx));
    // Decide connection state (socket). Use -1 for INVALID_SOCKET (as upstream uses).
    if(read_u8(tmp8)){
        ctx.sock = (tmp8 & 1) ? 1 : -1;
    } else {
        ctx.sock = (Size & 1) ? 1 : -1;
    }

    // qos value (0..2)
    int qos = 1;
    if(read_u8(tmp8)){
        qos = tmp8 % 3;
    } else {
        qos = (int)(Size % 3);
    }

    // Call the project's function under test.
    // db__ready_for_queue is declared in the included header and defined in the project sources.
    (void)db__ready_for_queue(&ctx, qos, &msg);

    return 0;
}
