#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include "mosquitto.h" /* brings in broker.h and broker_control.h via includes in the tree */
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include <cjson/cJSON.h>
}

/* uthash is included inside dynamic_security.h, so HASH_ADD_KEYPTR/HASH_DEL/HASH_FIND are available */

/* Helper: make a short printable string from binary input */
static std::string make_printable_string(const uint8_t *Data, size_t Size, size_t maxlen)
{
    std::string out;
    if(Size == 0 || maxlen == 0) return out;
    size_t take = (Size < maxlen) ? Size : maxlen;
    out.reserve(take);
    for(size_t i=0;i<take;i++){
        /* Map byte to printable lowercase letter to avoid embedded nulls */
        char c = 'a' + (Data[i] % 26);
        out.push_back(c);
    }
    return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr || Size == 0){
        return 0;
    }

    /* Minimal dynsec__data initialization */
    struct dynsec__data *data = (struct dynsec__data *)calloc(1, sizeof(struct dynsec__data));
    if(!data) return 0;
    data->clients = NULL;
    data->groups = NULL;
    data->roles = NULL;
    data->anonymous_group = NULL;
    data->kicklist = NULL;
    data->config_file = NULL;
    data->password_init_file = NULL;
    data->changeindex = 0;
    data->init_mode = 0;
    data->need_save = false;
    data->default_access.publish_c_recv = data->default_access.publish_c_send =
        data->default_access.subscribe = data->default_access.unsubscribe = false;

    /* Create a deterministic username derived from the input so the fuzzer can control it */
    std::string username = make_printable_string(Data, Size, 12);
    if(username.empty()){
        username = "fuzzuser";
    }

    /* Allocate a dynsec__client with flexible array username[] */
    size_t uname_len = username.length();
    struct dynsec__client *client = (struct dynsec__client *)malloc(sizeof(struct dynsec__client) + uname_len + 1);
    if(!client){
        free(data);
        return 0;
    }
    /* Zero the fixed part, then copy username into flexible array */
    memset(client, 0, sizeof(struct dynsec__client));
    memcpy(client->username, username.c_str(), uname_len + 1);

    /* initialize other fields */
    client->pw = NULL;
    client->rolelist = NULL;
    client->grouplist = NULL;
    client->clientid = NULL;
    client->text_name = NULL;
    client->text_description = NULL;
    client->disabled = false;

    /* Add client into the data->clients hash so dynsec_clients__find can locate it */
    HASH_ADD_KEYPTR(hh, data->clients, client->username, (unsigned)strlen(client->username), client);

    /* Build a mosquitto_control_cmd */
    struct mosquitto_control_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    /* Leave cmd.client == NULL so mosquitto_client_id/username will return NULL safely */
    cmd.client = NULL;
    cmd.j_responses = NULL;

    /* Create a JSON command object, ensure "username" exists and matches the client */
    cJSON *j_command = cJSON_CreateObject();
    if(!j_command){
        /* cleanup */
        HASH_DEL(data->clients, client);
        free(client);
        free(data);
        return 0;
    }
    cJSON_AddStringToObject(j_command, "username", client->username);

    /* Use some of the fuzz bytes to add optional fields to exercise code paths.
     * We avoid adding "password" to prevent calling client__set_password which may have more complex side effects.
     * We do add clientid/textname/textdescription to exercise allocation/freeing paths.
     */
    std::string extra = make_printable_string(Data, Size, 48);
    if(!extra.empty()){
        cJSON_AddStringToObject(j_command, "clientid", extra.c_str());
        cJSON_AddStringToObject(j_command, "textname", extra.c_str());
        cJSON_AddStringToObject(j_command, "textdescription", extra.c_str());
    }

    cmd.j_command = j_command;
    cmd.correlation_data = NULL;
    cmd.command_name = NULL;

    /* Call the function under test */
    /* The function may modify the data and client; call it once per input */
    (void)dynsec_clients__process_modify(data, &cmd);

    /* Clean up:
     * - cJSON object (function may modify it but it shouldn't delete it)
     * - remove and free client if still present
     * - free data
     */
    if(cmd.j_command){
        cJSON_Delete(cmd.j_command);
        cmd.j_command = NULL;
    }
    if(cmd.j_responses){
        cJSON_Delete(cmd.j_responses);
        cmd.j_responses = NULL;
    }

    /* Remove client from hash if still present and free resources allocated locally.
     * The function might have modified client->clientid/text_name/text_description; free them safely.
     */
    struct dynsec__client *found = NULL;
    if(data->clients){
        HASH_FIND(hh, data->clients, client->username, (unsigned)strlen(client->username), found);
    }
    if(found){
        /* detach and free */
        HASH_DEL(data->clients, found);
        mosquitto_pw_cleanup(found->pw); /* safe if NULL */
        if(found->clientid) mosquitto_free(found->clientid);
        if(found->text_name) mosquitto_free(found->text_name);
        if(found->text_description) mosquitto_free(found->text_description);
        dynsec_rolelist__cleanup(&found->rolelist);
        /* Free the client struct memory */
        free(found);
    } else {
        /* If not found, still free our allocated memory if it hasn't been freed by the function */
        /* We don't know if the function freed it; but free(NULL) is safe. To avoid double-free risk,
         * we only free if client pointer still appears to be allocated (heuristic: assume it's ours)
         */
        /* For safety, do nothing here if it was removed. */
    }

    /* Clean up any kicklist entries allocated by the function to avoid leaks */
    dynsec_kicklist__cleanup(data);

    free(data);

    return 0;
}