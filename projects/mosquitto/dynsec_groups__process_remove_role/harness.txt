#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <cstdlib>

// The dynamic-security plugin, broker control and cJSON are C libraries.
// When including C headers in a C++ translation unit, wrap them in extern "C"
// to ensure C linkage (avoid name mangling).
extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/mosquitto/include/mosquitto/broker_control.h"
#include "/src/cJSON/cJSON.h"
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Defensive: allow zero-size input, handle accordingly.
    // We'll split the input into two pieces: groupname and rolename.
    std::string all;
    if(Size > 0){
        all.assign(reinterpret_cast<const char*>(Data), Size);
    }else{
        all = std::string();
    }

    size_t mid = (all.size() / 2);

    std::string groupname = all.substr(0, mid);
    std::string rolename = all.substr(mid);

    // Create a cJSON object representing the command
    cJSON *j_command = cJSON_CreateObject();
    if(!j_command){
        return 0;
    }

    // Add groupname and rolename fields (they can be empty strings)
    // cJSON_AddStringToObject accepts C strings (null-terminated). Use .c_str() which is safe.
    cJSON_AddStringToObject(j_command, "groupname", groupname.c_str());
    cJSON_AddStringToObject(j_command, "rolename", rolename.c_str());

    // Prepare a mosquitto_control_cmd structure
    struct mosquitto_control_cmd cmd;
    std::memset(&cmd, 0, sizeof(cmd));
    cmd.client = nullptr; /* keep client NULL to avoid needing a full mosquitto client */
    cmd.j_command = j_command;
    cmd.j_responses = cJSON_CreateArray();
    cmd.correlation_data = nullptr;
    cmd.command_name = "removeGroupRole";

    // Prepare a dynsec__data structure (zero-initialised; groups/roles NULL)
    struct dynsec__data data;
    std::memset(&data, 0, sizeof(data));
    data.config_file = nullptr;
    data.password_init_file = nullptr;
    data.clients = nullptr;
    data.groups = nullptr;
    data.roles = nullptr;
    data.anonymous_group = nullptr;
    data.kicklist = nullptr;
    data.changeindex = 0;
    data.init_mode = 0;
    data.need_save = false;

    // Call the target function under test.
    // Wrapping the header with extern "C" ensures this resolves to the C symbol.
    (void)dynsec_groups__process_remove_role(&data, &cmd);

    // Cleanup cJSON objects
    if(cmd.j_responses){
        cJSON_Delete(cmd.j_responses);
        cmd.j_responses = nullptr;
    }
    if(j_command){
        cJSON_Delete(j_command);
        j_command = nullptr;
    }

    return 0;
}
