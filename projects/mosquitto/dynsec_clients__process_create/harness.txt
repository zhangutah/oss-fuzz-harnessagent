// Generate a fuzz driver based the given function signature in CPP language.
// The following fuzz driver exercises:
//   int dynsec_clients__process_create(struct dynsec__data * data, struct mosquitto_control_cmd * cmd);
//
// Build assumptions:
// - This harness is intended to be built and linked against the mosquitto project sources/libraries.
// - The absolute header paths below match the workspace layout discovered by the analysis tools.
//
// Entry point for libFuzzer:
extern "C" {
#include "/src/mosquitto/lib/mosquitto_internal.h" // include internal/mosquitto config first to set uthash macros
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/mosquitto/include/mosquitto/broker_control.h"
}
// Note: dynamic_security.h already includes cJSON and uthash as needed.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// libFuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Prepare a null-terminated copy of the input for cJSON parsing / string fields.
    char *buf = (char*)malloc(Size + 1);
    if(!buf) return 0;
    if(Size > 0 && Data) {
        memcpy(buf, Data, Size);
    }
    buf[Size] = '\0';

    // Try to parse input as JSON. If parsing fails, create a JSON object and
    // place the raw input into the "username" field so the target function
    // receives a valid cJSON object and we exercise its validation logic.
    cJSON *j_command = cJSON_Parse(buf);
    if(!j_command){
        j_command = cJSON_CreateObject();
        if(j_command){
            // Ensure username is present so function will attempt processing.
            cJSON_AddStringToObject(j_command, "username", buf);
            // Also add a password field for extra coverage.
            cJSON_AddStringToObject(j_command, "password", "");
        }
    }

    // Prepare a minimal dynsec__data structure. Zero-init to avoid uninitialized reads.
    struct dynsec__data data;
    memset(&data, 0, sizeof(data));
    data.clients = NULL;
    data.groups = NULL;
    data.roles = NULL;
    data.anonymous_group = NULL;
    data.kicklist = NULL;
    data.need_save = false;
    data.changeindex = 0;
    data.init_mode = 0;

    // Prepare a minimal mosquitto client context. The target function only uses
    // the client for logging via mosquitto_client_id/username; zero-init is fine.
    struct mosquitto client;
    memset(&client, 0, sizeof(client));

    // Prepare the control command struct expected by the function.
    struct mosquitto_control_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.client = &client;
    cmd.j_command = j_command;
    // Provide a responses container so mosquitto_control_command_reply can operate.
    cmd.j_responses = cJSON_CreateArray();
    cmd.correlation_data = NULL;
    cmd.command_name = "createClient";

    // Call the target function. This is the function under test.
    // It will read values from cmd.j_command (the JSON) and from data.
    // The function may allocate entries in data->clients; we clean them up after.
    (void)dynsec_clients__process_create(&data, &cmd);

    // Cleanup: free any dynamic structures created by the target and by this harness.
    // dynsec_clients__cleanup will remove/free any clients added to data->clients.
    dynsec_clients__cleanup(&data);

    if(cmd.j_responses){
        cJSON_Delete(cmd.j_responses);
        cmd.j_responses = NULL;
    }
    if(j_command){
        cJSON_Delete(j_command);
        j_command = NULL;
    }
    free(buf);

    return 0;
}
