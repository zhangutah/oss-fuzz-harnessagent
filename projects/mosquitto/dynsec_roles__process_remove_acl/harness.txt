#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/mosquitto/include/mosquitto/broker_control.h"

// Undef uthash allocator macros if they were already defined earlier
// so config.h can (re)define them as needed without causing a macro
// redefinition error.
#ifdef uthash_malloc
#undef uthash_malloc
#endif
#ifdef uthash_free
#undef uthash_free
#endif

// Include the internal header so struct mosquitto is a complete type here.
#include "/src/mosquitto/lib/mosquitto_internal.h"
#include <cjson/cJSON.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Split input bytes into three roughly-equal parts for rolename, acltype and topic.
    size_t part1 = Size / 3;
    size_t part2 = (Size - part1) / 2;
    size_t part3 = Size - part1 - part2;

    // Ensure at least something in each part.
    if(part1 == 0) part1 = 1;
    if(part2 == 0 && (Size - part1) > 1) part2 = 1;
    part3 = (Size > part1 + part2) ? (Size - part1 - part2) : 0;

    std::string rolename;
    std::string acltype;
    std::string topic;

    // Build strings (may contain embedded nulls; cJSON takes C strings, so make sure
    // the std::string is null-terminated via c_str()).
    rolename.assign(reinterpret_cast<const char*>(Data), part1);
    acltype.assign(reinterpret_cast<const char*>(Data + part1), part2);
    topic.assign(reinterpret_cast<const char*>(Data + part1 + part2), part3);

    // If any string is empty, give it a small default to exercise logic paths.
    if(rolename.empty()) rolename = "role";
    // If ACL_TYPE_SUB_LITERAL is not available for some build configurations, fall back to "subscribe".
#ifdef ACL_TYPE_SUB_LITERAL
    if(acltype.empty()) acltype = ACL_TYPE_SUB_LITERAL; // use a valid acltype constant
#else
    if(acltype.empty()) acltype = "subscribe";
#endif
    if(topic.empty()) topic = "test/topic";

    // Construct cJSON command object
    cJSON *j_command = cJSON_CreateObject();
    if(!j_command) return 0;

    // Add command fields
    // Use cJSON_AddStringToObject which copies the string value.
    cJSON_AddStringToObject(j_command, "rolename", rolename.c_str());
    cJSON_AddStringToObject(j_command, "acltype", acltype.c_str());
    cJSON_AddStringToObject(j_command, "topic", topic.c_str());

    // Construct responses array (used by mosquitto_control_command_reply)
    cJSON *j_responses = cJSON_CreateArray();
    if(!j_responses){
        cJSON_Delete(j_command);
        return 0;
    }

    // Prepare a minimal mosquitto struct for cmd->client so that logging lookups succeed.
    // The internal header provides the complete struct definition so sizeof is valid.
    struct mosquitto *client = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!client){
        cJSON_Delete(j_responses);
        cJSON_Delete(j_command);
        return 0;
    }
    // The plugin_public.c implementation of mosquitto_client_id and _username expect
    // client->id and client->username fields to be pointers to strings.
    // We set small strings here.
    client->id = strdup("fuzz-client");
    client->username = strdup("fuzz-user");

    // Build the control command
    struct mosquitto_control_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.client = client;
    cmd.j_command = j_command;
    cmd.j_responses = j_responses;
    cmd.correlation_data = NULL;
    cmd.command_name = "removeRoleACL";

    // Minimal dynsec__data (roles list is NULL -> role not found path is exercised).
    struct dynsec__data data;
    memset(&data, 0, sizeof(data));
    data.roles = NULL;
    data.kicklist = NULL;
    data.clients = NULL;
    data.groups = NULL;
    data.config_file = NULL;
    data.password_init_file = NULL;
    data.need_save = false;
    data.changeindex = 0;
    data.init_mode = 0;

    // Call the target function.
    // The function may reply via cmd.j_responses; it's fine for fuzzing harness.
    (void)dynsec_roles__process_remove_acl(&data, &cmd);

    // Cleanup
    if(client){
        if(client->id) { free((void*)client->id); client->id = NULL; }
        if(client->username) { free((void*)client->username); client->username = NULL; }
        free(client);
    }
    cJSON_Delete(j_responses);
    cJSON_Delete(j_command);

    return 0;
}
