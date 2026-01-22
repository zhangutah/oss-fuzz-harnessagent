#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>

// The dynamic-security and cJSON headers are C headers. When included
// in a C++ translation unit they must be wrapped in extern "C" to
// ensure correct (C) linkage and avoid name-mangling mismatches.
extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/cJSON/cJSON.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Defend against null pointer input (shouldn't normally happen).
    if (Data == nullptr || Size == 0) {
        return 0;
    }

    // Parse the provided bytes as JSON. cJSON_ParseWithLength is safe for non-null-terminated buffers.
    const char *buf = reinterpret_cast<const char *>(Data);
    cJSON *tree = cJSON_ParseWithLength(buf, Size);
    if (tree == nullptr) {
        // Not valid JSON; nothing to do.
        return 0;
    }

    // Prepare a clean dynsec__data structure. Zeroing ensures pointers (like groups)
    // are NULL so the code inside dynsec_groups__config_load and cleanup behaves.
    struct dynsec__data data;
    std::memset(&data, 0, sizeof(data));

    // Call the target function under test.
    // dynsec_groups__config_load may allocate group structures and attach them to data.groups.
    (void)dynsec_groups__config_load(&data, tree);

    // Ensure any allocated groups are cleaned up to avoid leaking memory between fuzzer runs.
    dynsec_groups__cleanup(&data);

    // Free the parsed JSON.
    cJSON_Delete(tree);

    return 0;
}
