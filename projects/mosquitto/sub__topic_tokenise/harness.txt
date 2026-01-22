// Fixed harness: ensure correct C linkage for C functions and provide missing symbols expected at link time.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

// Include project headers (absolute paths as returned by analysis tools).
// Wrap C headers in extern "C" so their declarations have C linkage when compiled as C++.
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/include/mosquitto/libcommon_memory.h"

// fuzz_packet_read_base.c expects these to be present (they are usually
// provided by other fuzz harness files). Provide prototypes so the
// definitions below match expected C linkage.
int fuzz_packet_read_init(struct mosquitto *context);
void fuzz_packet_read_cleanup(struct mosquitto *context);
} // extern "C"

// Simple, safe stub implementations to satisfy the linker.
// They intentionally do minimal work; adjust if the project requires more.
extern "C" int fuzz_packet_read_init(struct mosquitto *context)
{
    (void)context;
    return 0;
}

extern "C" void fuzz_packet_read_cleanup(struct mosquitto *context)
{
    (void)context;
}

// Fuzzer entry point required by libFuzzer. Use C linkage as requested.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Protect against null input pointers.
    if (Data == nullptr) return 0;

    // Convert input bytes into a null-terminated C string.
    // sub__topic_tokenise expects a C string (uses strlen), so ensure termination.
    std::string tmp(reinterpret_cast<const char*>(Data), Size);
    tmp.push_back('\0'); // ensure null termination

    char *local_sub = nullptr;
    char **topics = nullptr;
    const char *sharename = nullptr;

    // Call the target function under test.
    // It will allocate local_sub and topics on success; check return code if needed.
    int rc = sub__topic_tokenise(tmp.c_str(), &local_sub, &topics, &sharename);
    (void)rc; // Mark rc as used to avoid -Werror,-Wunused-variable

    // Clean up any allocated memory. The function uses mosquitto_malloc/calloc, so
    // free with the provided mosquitto_FREE macro (which calls mosquitto_free()).
    if (local_sub) {
        mosquitto_FREE(local_sub);
    }
    if (topics) {
        // topics is an array allocated by mosquitto_calloc; its elements point into local_sub
        // (so we must not attempt to free individual topic strings). Free the array itself.
        mosquitto_FREE(topics);
    }

    // We don't need to use rc or sharename here; just ensure no undefined behavior.

    return 0;
}
