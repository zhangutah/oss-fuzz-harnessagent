// Fixed fuzz driver for dynsec_clients__process_get
// Removed local stub for dynsec_clients__process_get so the real implementation
// from the project is used. Left minimal stubs for fuzz_packet_read_init and
// fuzz_packet_read_cleanup which other object files expect at link time.
//
// Do not change the fuzzer entry function signature.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <cstdlib>

// The project headers are C headers. Wrap them in extern "C" so the declarations
// have C linkage when compiled as C++.
extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
#include "/src/mosquitto/include/mosquitto/broker_control.h"
}

// Forward declare struct mosquitto in case it isn't pulled in by the above headers.
struct mosquitto;

// Provide stubs for fuzz_packet_read_init and fuzz_packet_read_cleanup which
// other object files expect at link time. Use C linkage to match the rest of the C code.
extern "C" int fuzz_packet_read_init(struct mosquitto *context)
{
    (void)context;
    return 0;
}

extern "C" void fuzz_packet_read_cleanup(struct mosquitto *context)
{
    (void)context;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	// Basic checks
	if(!Data || Size == 0) return 0;

	// Convert fuzz data to a std::string (may contain NULs, but cJSON will read up to first NUL).
	// To avoid extremely large allocations, limit the username length.
	size_t maxlen = 1024;
	size_t use_len = Size < maxlen ? Size : maxlen;
	std::string username(reinterpret_cast<const char*>(Data), use_len);

	// Prepare minimal dynsec__data with zeroed fields
	struct dynsec__data data;
	memset(&data, 0, sizeof(data));
	// Ensure the client hash is NULL (no clients)
	data.clients = NULL;
	data.groups = NULL;
	data.roles = NULL;
	data.anonymous_group = NULL;
	data.kicklist = NULL;

	// Prepare control command
	struct mosquitto_control_cmd cmd;
	memset(&cmd, 0, sizeof(cmd));

	// j_command must contain a "username" string as expected by dynsec_clients__process_get
	cmd.j_command = cJSON_CreateObject();
	if(!cmd.j_command){
		// Out of memory or other cJSON error; nothing to do.
		return 0;
	}
	// cJSON_AddStringToObject will add a null-terminated string;
	// if username contains embedded NULs, only the prefix up to the first NUL is used.
	cJSON_AddStringToObject(cmd.j_command, "username", username.c_str());

	// Prepare responses array expected by the function
	cmd.j_responses = cJSON_CreateArray();
	// No actual mosquitto client context is needed for this test; set to NULL.
	cmd.client = NULL;
	cmd.correlation_data = NULL;
	cmd.command_name = "getClient";

	// Call the target function under test (the real implementation from the project).
	(void)dynsec_clients__process_get(&data, &cmd);

	// Clean up cJSON objects allocated here and any responses produced
	if(cmd.j_command){
		cJSON_Delete(cmd.j_command);
		cmd.j_command = NULL;
	}
	if(cmd.j_responses){
		cJSON_Delete(cmd.j_responses);
		cmd.j_responses = NULL;
	}

	// No dynamic allocations in dynsec__data were made here, so nothing more to free.
	return 0;
}
