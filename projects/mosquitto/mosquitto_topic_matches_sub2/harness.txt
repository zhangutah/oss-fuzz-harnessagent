// Fixed harness for mosquitto_topic_matches_sub2
// Path: /src/mosquitto/fuzzing/apps/db_dump/db_dump_fuzz_load.cpp
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

// The mosquitto headers use libmosqcommon_EXPORT for symbol visibility.
// In this build environment that macro may not be defined, which causes
// "unknown type name 'libmosqcommon_EXPORT'" errors. Define it as empty
// so the header declarations compile cleanly.
#ifndef libmosqcommon_EXPORT
#define libmosqcommon_EXPORT
#endif

// Include the header that declares mosquitto_topic_matches_sub2.
// Use the project absolute path discovered previously.
#include "/src/mosquitto/include/mosquitto/libcommon_topic.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Need at least two bytes so we can produce a non-empty subscription and topic.
    // The original harness allowed zero-length sub/topic (passing nullptr),
    // which caused mosquitto_topic_matches_sub2 to return early (MOSQ_ERR_INVAL),
    // reducing useful coverage. Require Size >= 2 so both parts are non-empty.
    if (Size < 2 || Data == nullptr) {
        return 0;
    }

    // We'll make up to 16 calls, but ensure each call uses non-empty sub/topic.
    const size_t max_calls = (Size < 17) ? (Size - 1) : 16;
    uint8_t seed = Data[0];

    for (size_t i = 0; i < max_calls; ++i) {
        // Choose a split in the range [1, Size-1] so both sublen and topiclen are > 0.
        size_t split = 1 + (static_cast<size_t>(seed) + i) % (Size - 1);

        size_t sublen = split;
        size_t topiclen = Size - split;

        // Create std::string copies so we have proper null-terminated buffers.
        // This ensures the fuzzer data actually influences program flow and
        // avoids passing nullptr for empty strings.
        std::string sub_str(reinterpret_cast<const char*>(Data), sublen);
        std::string topic_str(reinterpret_cast<const char*>(Data + split), topiclen);

        const char *sub_ptr = sub_str.c_str();
        const char *topic_ptr = topic_str.c_str();

        bool result = false;
        // Call the target function. We intentionally do not check the return
        // value here; the fuzzer's job is to see if any inputs cause crashes
        // or undefined behavior.
        mosquitto_topic_matches_sub2(sub_ptr, sublen, topic_ptr, topiclen, &result);

        // Use the result in a no-op way to prevent the compiler from optimizing away
        // anything dependent on it (defensive; not strictly necessary, but harmless).
        (void)result;
    }

    return 0;
}
