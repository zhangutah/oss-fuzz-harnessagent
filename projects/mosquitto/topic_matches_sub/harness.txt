// Fixed broker_fuzz_queue_msg.cpp
// Ensures the mosquitto_calloc macro does not break header declarations by
// including the public headers first (so include guards prevent re-expansion),
// then defining a helper macro used only for the subsequently included C source.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cstdlib>
#include <cstdbool>

// Include the public mosquitto header first so that the declaration of
// mosquitto_calloc in libcommon_memory.h is processed before we define a
// replacement macro. The include has its own include guards, so when we later
// include the C source (topic_common.c) the header won't be reprocessed and
// won't see our macro.
#include "/src/mosquitto/include/mosquitto.h"

// Provide a C++-friendly replacement for mosquitto_calloc only within this TU.
// We want expressions like:
//    some_typed_ptr = mosquitto_calloc(...);
// to automatically cast to the appropriate pointer type. We implement a small
// helper with a templated conversion operator that performs a reinterpret_cast
// from calloc's result.
struct mosq_calloc_helper {
    size_t nmemb;
    size_t size;
    mosq_calloc_helper(size_t n, size_t s) : nmemb(n), size(s) {}
    template<typename T>
    operator T() const {
        return reinterpret_cast<T>(calloc(nmemb, size));
    }
};

// Define macro to replace mosquitto_calloc calls in the included C file.
// Because we already included the headers above, the prototype for
// mosquitto_calloc has been seen and won't be corrupted by this macro.
#define mosquitto_calloc(nmemb, size) mosq_calloc_helper((nmemb), (size))

// Include the C source directly so we can call the static function topic_matches_sub.
// Use extern "C" for correct linkage of any C symbols.
extern "C" {
#include "/src/mosquitto/libcommon/topic_common.c"
}

// Undo macro so it doesn't leak later (clean).
#undef mosquitto_calloc

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if(!Data || Size == 0) return 0;

    // Use the final input byte as flags:
    // bit 0: match_patterns
    // bit 1: make clientid NULL
    // bit 2: make username NULL
    // bit 3: pass result as NULL
    uint8_t flags = Data[Size - 1];

    bool match_patterns = (flags & 0x01) != 0;
    bool make_clientid_null = (flags & 0x02) != 0;
    bool make_username_null = (flags & 0x04) != 0;
    bool make_result_null   = (flags & 0x08) != 0;

    // Split the input (excluding the last byte) into four parts for sub, topic, clientid, username.
    size_t payload_size = (Size >= 1) ? Size - 1 : 0;
    const uint8_t *payload = Data;

    std::string parts[4];
    if(payload_size > 0) {
        size_t base_chunk = payload_size / 4;
        size_t extra = payload_size % 4;
        size_t off = 0;
        for(int i = 0; i < 4; ++i) {
            size_t len = base_chunk + (i < (int)extra ? 1 : 0);
            if(len > 0) {
                parts[i].assign((const char*)(payload + off), len);
            } else {
                parts[i].clear();
            }
            off += len;
        }
    } else {
        // No payload -> empty strings
        parts[0].clear();
        parts[1].clear();
        parts[2].clear();
        parts[3].clear();
    }

    const char *sub = parts[0].c_str();
    const char *topic = parts[1].c_str();
    const char *clientid = make_clientid_null ? nullptr : parts[2].c_str();
    const char *username = make_username_null ? nullptr : parts[3].c_str();

    // Prepare result pointer (can be NULL based on flags)
    bool result_val = false;
    bool *result_ptr = make_result_null ? nullptr : &result_val;

    // Call the target function. It's defined static in the included C file so we can call it directly.
    (void)topic_matches_sub(sub, topic, clientid, username, match_patterns, result_ptr);

    // Also try a couple of additional call variations to exercise different code paths:
    (void)topic_matches_sub(sub, topic, clientid, username, !match_patterns, result_ptr);

    return 0;
}