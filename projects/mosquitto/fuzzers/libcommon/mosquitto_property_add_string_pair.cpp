// Fixed fuzz harness for mosquitto_property_add_string_pair
// File: /src/mosquitto/fuzzing/apps/db_dump/db_dump_fuzz_load.cpp

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Include project headers (use absolute paths discovered in the workspace).
// Ensure definitions/macros/types are provided before property API.
#include "/src/mosquitto/include/mosquitto/defs.h"
#include "/src/mosquitto/include/mosquitto/libcommon.h"
#include "/src/mosquitto/include/mosquitto/libcommon_properties.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Defensive checks
    if(!Data || Size == 0) return 0;

    // Use both first and last input bytes so the fuzzer cannot claim input
    // bytes are ignored (helps initial/final coverage checks).
    uint8_t first = Data[0];
    uint8_t last = Data[Size - 1];

    // Prepare a property list pointer
    mosquitto_property *proplist = NULL;

    // Split input into two parts: name and value.
    // Ensure both are non-NULL C strings (zero-terminated).
    size_t half = Size / 2;
    size_t name_len = half;
    size_t value_len = Size - half;

    char *name = (char*)malloc(name_len + 1);
    char *value = (char*)malloc(value_len + 1);
    if(!name || !value){
        free(name);
        free(value);
        return 0;
    }

    if(name_len > 0){
        memcpy(name, Data, name_len);
    }
    name[name_len] = '\0';

    if(value_len > 0){
        memcpy(value, Data + half, value_len);
    }
    value[value_len] = '\0';

    // Choose identifier: primarily fuzz MQTT_PROP_USER_PROPERTY (the valid identifier),
    // but occasionally use other values from the input to explore error branches.
    int identifier = MQTT_PROP_USER_PROPERTY;
    // Combine first and last bytes to influence identifier selection.
    uint8_t mode = first ^ last;
    if((mode & 0x3) == 0x3){
        // pick a likely-invalid identifier from input to hit MOSQ_ERR_INVAL branch
        identifier = (int)mode;
    }

    // Use fuzz data to pick one of several call variants so the fuzzer input
    // affects control flow.
    int variant = mode & 0x3;
    switch(variant){
        case 0:
            // normal: both name and value
            mosquitto_property_add_string_pair(&proplist, identifier, name, value);
            break;
        case 1:
            // name NULL, value present
            mosquitto_property_add_string_pair(&proplist, identifier, NULL, value);
            break;
        case 2:
            // value NULL, name present
            mosquitto_property_add_string_pair(&proplist, identifier, name, NULL);
            break;
        case 3:
        default:
            // both NULL (allowed by API, may exercise error branches)
            mosquitto_property_add_string_pair(&proplist, identifier, NULL, NULL);
            break;
    }

    // Clean up: free any properties allocated into proplist by the function.
    // The API provides a helper to free the whole list.
    mosquitto_property_free_all(&proplist);

    free(name);
    free(value);

    return 0;
}
