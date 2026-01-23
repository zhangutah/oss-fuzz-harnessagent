// Generate a fuzz driver based the given function signature in CPP language. 
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     int dynsec_auth__basic_auth_callback(int event, void * event_data, void * userdata);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
// Fuzzer driver for:
//   int dynsec_auth__basic_auth_callback(int event, void * event_data, void * userdata);

// Builds a simple dynsec__data and mosquitto_evt_basic_auth and calls the target function.
// Keeps allocations bounded and avoids invoking parts of the code that require additional
// complex initialization (e.g., mosquitto_client_id() and real mosquitto_pw verification).

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <algorithm>

// Include the plugin header with C linkage to match the C implementation.
extern "C" {
#include "/src/mosquitto/plugins/dynamic-security/dynamic_security.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr || Size == 0) return 0;

    // Bound lengths to avoid huge allocations in fuzz environment.
    const size_t MAX_PART = 256;

    // Split input roughly into username and password parts.
    size_t split = Size / 2;
    size_t uname_len = std::min(split, MAX_PART);
    size_t pass_len = std::min(Size - split, (size_t)MAX_PART);

    // If split yields zero-length username, try to ensure at least 1 byte if possible.
    if(uname_len == 0 && Size > 0){
        uname_len = std::min(Size, (size_t)1);
        pass_len = std::min(Size - uname_len, MAX_PART);
    }

    // Prepare username and password buffers (null-terminated).
    char uname_buf[MAX_PART + 1];
    char pass_buf[MAX_PART + 1];
    memset(uname_buf, 0, sizeof(uname_buf));
    memset(pass_buf, 0, sizeof(pass_buf));
    memcpy(uname_buf, Data, uname_len);
    memcpy(pass_buf, Data + split, pass_len);

    // Build dynsec__data with one client whose username matches uname_buf.
    struct dynsec__data data;
    memset(&data, 0, sizeof(data));
    data.clients = NULL;

    // Allocate a dynsec__client with space for the flexible username[] member.
    size_t client_alloc = sizeof(struct dynsec__client) + strlen(uname_buf) + 1;
    struct dynsec__client *client = (struct dynsec__client *)malloc(client_alloc);
    if(client){
        // Zero initialize up to the username flexible array.
        memset(client, 0, client_alloc);
        client->pw = NULL;            // leave pw NULL to avoid complex pw setup
        client->rolelist = NULL;
        client->grouplist = NULL;
        client->clientid = NULL;      // avoid path that calls mosquitto_client_id()
        client->text_name = NULL;
        client->text_description = NULL;
        client->disabled = false;     // default enabled; content of Data could be used to toggle
        // Copy username into flexible array
        strcpy(client->username, uname_buf);

        // Add to hash table keyed by username
        HASH_ADD_KEYPTR(hh, data.clients, client->username, (unsigned)strlen(client->username), client);
    }

    // Prepare event_data: mosquitto_evt_basic_auth
    struct mosquitto_evt_basic_auth ed;
    memset(&ed, 0, sizeof(ed));
    ed.client = NULL; // client pointer left NULL; clientid checks skipped because client->clientid is NULL
    // Let the event username point to the stored client's username when present (to exercise find).
    if(client){
        ed.username = client->username;
    }else{
        // No client inserted: set username to the fuzzed username buffer (may be empty)
        // allocate a copy so dynsec code can read it safely
        ed.username = strdup(uname_buf);
    }
    // Password: allocate a copy of pass_buf (null-terminated)
    ed.password = strdup(pass_buf);

    // Call the target function with event 0
    (void)dynsec_auth__basic_auth_callback(0, &ed, &data);

    // Cleanup
    if(ed.username && client == NULL){
        free((void*)ed.username);
    }
    if(ed.password){
        free((void*)ed.password);
    }

    // Remove and free all clients in the hash table
    if(data.clients){
        struct dynsec__client *cur, *tmp;
        HASH_ITER(hh, data.clients, cur, tmp){
            HASH_DEL(data.clients, cur);
            free(cur);
        }
    }

    return 0;
}
