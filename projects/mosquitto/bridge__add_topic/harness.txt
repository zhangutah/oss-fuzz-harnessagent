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
// // Example 1:
// 
// // static void map_invalid_helper(const char *topic, const char *local_prefix, const char *remote_prefix)
// //{
// //	struct mosquitto mosq;
// //	struct mosquitto__bridge bridge;
// //	int rc;
// //
// //	memset(&mosq, 0, sizeof(struct mosquitto));
// //	memset(&bridge, 0, sizeof(struct mosquitto__bridge));
// //
// //	mosq.bridge = &bridge;
// //
// //	rc = bridge__add_topic(&bridge, topic, bd_in, 0, local_prefix, remote_prefix);
// //	CU_ASSERT_NOT_EQUAL(rc, 0);
// //
// //	bridge__cleanup_topics(&bridge);
// //}
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     int bridge__add_topic(struct mosquitto__bridge * bridge, const char * topic, enum mosquitto__bridge_direction direction, uint8_t qos, const char * local_prefix, const char * remote_prefix);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
// Fuzz driver for:
// int bridge__add_topic(struct mosquitto__bridge * bridge, const char * topic,
//                       enum mosquitto__bridge_direction direction, uint8_t qos,
//                       const char * local_prefix, const char * remote_prefix);
// Fuzzer entry point: LLVMFuzzerTestOneInput

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "mosquitto_broker_internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size < 1) return 0;

    // Prepare a bridge object, zero-initialised.
    struct mosquitto__bridge bridge;
    memset(&bridge, 0, sizeof(bridge));

    // Interpret the first two bytes as control bytes (if present).
    uint8_t control = Data[0];
    uint8_t qos = 0;
    if(Size > 1){
        qos = Data[1];
    }

    // Bits in control:
    // bits 0-1 : direction (0..3) -> map to 0..2 (bd_out, bd_in, bd_both)
    // bit 2    : set topic to NULL instead of using provided bytes
    // bit 3    : set topic to the literal "\"\"" (empty-mapped topic)
    // bit 4    : local_prefix NULL flag
    // bit 5    : remote_prefix NULL flag
    uint8_t dir_val = control & 0x3;
    enum mosquitto__bridge_direction direction = bd_out;
    if((dir_val % 3) == 0) direction = bd_out;
    else if((dir_val % 3) == 1) direction = bd_in;
    else direction = bd_both;

    bool topic_null_flag = (control & 0x04) != 0;
    bool topic_empty_literal = (control & 0x08) != 0;
    bool local_null_flag = (control & 0x10) != 0;
    bool remote_null_flag = (control & 0x20) != 0;

    // Extract up to three NUL-separated strings from Data starting at offset 2.
    // If not enough bytes available, strings may be empty.
    size_t pos = 2;
    size_t end = Size;

    auto extract_next = [&](void) -> char* {
        if(pos >= end){
            // Return an empty string (not NULL) so the target sees "".
            char *s = (char*)malloc(1);
            if(s) s[0] = '\0';
            return s;
        }
        size_t start = pos;
        while(pos < end && Data[pos] != '\0') pos++;
        size_t len = pos - start;
        char *s = (char*)malloc(len + 1);
        if(!s) return nullptr;
        if(len) memcpy(s, Data + start, len);
        s[len] = '\0';
        if(pos < end) pos++; // skip the NUL separator
        return s;
    };

    char *topic_s = nullptr;
    char *local_s = nullptr;
    char *remote_s = nullptr;

    // Build strings unless flags indicate NULL or set special literal.
    if(topic_null_flag){
        topic_s = nullptr;
    }else if(topic_empty_literal){
        topic_s = (char*)malloc(4);
        if(topic_s) strcpy(topic_s, "\"\"");
    }else{
        topic_s = extract_next();
    }

    if(local_null_flag){
        local_s = nullptr;
    }else{
        local_s = extract_next();
    }

    if(remote_null_flag){
        remote_s = nullptr;
    }else{
        remote_s = extract_next();
    }

    // Call the function under test.
    // Note: qos is an uint8_t; bridge__add_topic checks qos > 2
    int rc = bridge__add_topic(&bridge, topic_s, direction, qos, local_s, remote_s);

    // Cleanup topics allocated by bridge__add_topic (if any).
    bridge__cleanup_topics(&bridge);

    // Free strings we allocated for the call.
    if(topic_s) free(topic_s);
    if(local_s) free(local_s);
    if(remote_s) free(remote_s);

    // Ignore return value; fuzzer looks for crashes/UB.
    (void)rc;
    return 0;
}
