#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/mosquitto/include/mosquitto/broker_control.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	// Create a JSON object to mimic a control command payload.
	// We place half of the input bytes into "username" and the rest into "rolename".
	cJSON *j_command = cJSON_CreateObject();
	if(!j_command) return 0;

	std::string username;
	std::string rolename;
	if(Size > 0){
		size_t split = Size / 2;
		username.assign((const char *)Data, split);
		rolename.assign((const char *)Data + split, Size - split);
	} else {
		username = "";
		rolename = "";
	}

	// cJSON_AddStringToObject expects NUL-terminated C strings.
	// std::string::c_str() provides that.
	if(cJSON_AddStringToObject(j_command, "username", username.c_str()) == NULL){
		cJSON_Delete(j_command);
		return 0;
	}
	if(cJSON_AddStringToObject(j_command, "rolename", rolename.c_str()) == NULL){
		cJSON_Delete(j_command);
		return 0;
	}

	// Prepare the control command structure expected by the function under test.
	struct mosquitto_control_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));
	cmd.client = NULL; // leave NULL so mosquitto_client_id/username return NULL safely
	cmd.j_command = j_command;
	cmd.j_responses = cJSON_CreateArray();
	cmd.correlation_data = NULL;
	cmd.command_name = "removeClientRole";

	if(!cmd.j_responses){
		cJSON_Delete(j_command);
		return 0;
	}

	// Prepare a minimal dynsec__data structure.
	struct dynsec__data data;
	memset(&data, 0, sizeof(data));
	// Leave lists (clients, roles, kicklist, etc.) as NULL to exercise
	// the code paths that handle missing entries.

	// Call the function under test with the constructed inputs.
	(void)dynsec_clients__process_remove_role(&data, &cmd);

	// Cleanup JSON objects created for this invocation.
	// The function under test may have appended responses to cmd.j_responses,
	// so delete that array (and any children) as well.
	cJSON_Delete(cmd.j_responses);
	cJSON_Delete(j_command);

	// Note: We do not free fields inside data because we didn't allocate them.
	// dynsec_clients__process_remove_role may call functions that set
	// data->need_save or add to kicklist; however, given we left clients/roles NULL,
	// the function will return early in most cases and not allocate persistent data.

	return 0;
}
