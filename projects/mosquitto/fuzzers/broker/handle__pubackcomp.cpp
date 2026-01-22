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
// // int handle__packet(struct mosquitto *mosq)
// //{
// //	int rc = MOSQ_ERR_INVAL;
// //	assert(mosq);
// //
// //	switch((mosq->in_packet.command)&0xF0){
// //		case CMD_PINGREQ:
// //			rc = handle__pingreq(mosq);
// //			break;
// //		case CMD_PINGRESP:
// //			rc = handle__pingresp(mosq);
// //			break;
// //		case CMD_PUBACK:
// //			rc = handle__pubackcomp(mosq, "PUBACK");
// //			break;
// //		case CMD_PUBCOMP:
// //			rc = handle__pubackcomp(mosq, "PUBCOMP");
// //			break;
// //		case CMD_PUBLISH:
// //			rc = handle__publish(mosq);
// //			break;
// //		case CMD_PUBREC:
// //			rc = handle__pubrec(mosq);
// //			break;
// //		case CMD_PUBREL:
// //			rc = handle__pubrel(mosq);
// //			break;
// //		case CMD_CONNACK:
// //			rc = handle__connack(mosq);
// //			break;
// //		case CMD_SUBACK:
// //			rc = handle__suback(mosq);
// //			break;
// //		case CMD_UNSUBACK:
// //			rc = handle__unsuback(mosq);
// //			break;
// //		case CMD_DISCONNECT:
// //			rc = handle__disconnect(mosq);
// //			break;
// //		case CMD_AUTH:
// //			rc = handle__auth(mosq);
// //			break;
// //		default:
// //			/* If we don't recognise the command, return an error straight away. */
// //			log__printf(mosq, MOSQ_LOG_ERR, "Error: Unrecognised command %d\n", (mosq->in_packet.command)&0xF0);
// //			rc = MOSQ_ERR_PROTOCOL;
// //			break;
// //	}
// //
// //	if(mosq->protocol == mosq_p_mqtt5){
// //		if(rc == MOSQ_ERR_PROTOCOL || rc == MOSQ_ERR_DUPLICATE_PROPERTY){
// //			send__disconnect(mosq, MQTT_RC_PROTOCOL_ERROR, NULL);
// //		}else if(rc == MOSQ_ERR_MALFORMED_PACKET || rc == MOSQ_ERR_MALFORMED_UTF8){
// //			send__disconnect(mosq, MQTT_RC_MALFORMED_PACKET, NULL);
// //		}else if(rc == MOSQ_ERR_QOS_NOT_SUPPORTED){
// //			send__disconnect(mosq, MQTT_RC_QOS_NOT_SUPPORTED, NULL);
// //		}else if(rc == MOSQ_ERR_RETAIN_NOT_SUPPORTED){
// //			send__disconnect(mosq, MQTT_RC_RETAIN_NOT_SUPPORTED, NULL);
// //		}else if(rc == MOSQ_ERR_TOPIC_ALIAS_INVALID){
// //			send__disconnect(mosq, MQTT_RC_TOPIC_ALIAS_INVALID, NULL);
// //		}else if(rc == MOSQ_ERR_RECEIVE_MAXIMUM_EXCEEDED){
// //			send__disconnect(mosq, MQTT_RC_RECEIVE_MAXIMUM_EXCEEDED, NULL);
// //		}else if(rc == MOSQ_ERR_UNKNOWN || rc == MOSQ_ERR_NOMEM){
// //			send__disconnect(mosq, MQTT_RC_UNSPECIFIED, NULL);
// //		}
// //	}
// //	return rc;
// //
// //}
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     int handle__pubackcomp(struct mosquitto * mosq, const char * type);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
// Fuzz driver for: int handle__pubackcomp(struct mosquitto *mosq, const char *type);
// Build as part of the mosquitto project (so project headers and compile flags are used).
//
// This driver treats the fuzzer input as the packet payload for mosq->in_packet.
// It picks the "type" argument ("pubAck" or "pubComp") based on the first byte
// of the input to exercise both code paths.
//
// Note: This file assumes the same build configuration as the mosquitto source
// (e.g., WITH_THREADING/non-broker config used when building handle__pubackcomp).
// Include it in the project's fuzz build so it links against the mosquitto internals.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <pthread.h>

extern "C" {
#include "mosquitto.h"
#include "mosquitto/mqtt_protocol.h"
#include "mosquitto_internal.h"
#include "read_handle.h"
}

// Prototype is provided by read_handle.h; handle__pubackcomp is defined in the project.
extern "C" int handle__pubackcomp(struct mosquitto *mosq, const char *type);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Minimal sanity: always return if Data is null (shouldn't happen), but handle gracefully.
    if (Data == nullptr) return 0;

    // Allocate and zero the mosquitto struct so unspecified fields start as 0/NULL.
    struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if (!mosq) return 0;

    // Initialize fields that handle__pubackcomp expects/uses.

    // 1) Client state: function checks mosquitto__get_state(mosq) == mosq_cs_active
    // mosquitto__get_state locks state_mutex internally, so initialize it if present.
#ifdef WITH_THREADING
    // Only initialize if the structure actually has state_mutex (project build config).
    // The internal header guards control whether state_mutex exists; initialize in all cases
    // because if it does not exist the compiler will fail and you'll need to match project flags.
    pthread_mutex_init(&mosq->state_mutex, NULL);
#endif
    mosq->state = mosq_cs_active;

    // 2) in_packet: point payload to fuzzer data and set lengths/pos/command
    mosq->in_packet.payload = (uint8_t *)Data; // cast away const for read-only access
    mosq->in_packet.remaining_length = (uint32_t)Size;
    mosq->in_packet.pos = 0;
    mosq->in_packet.remaining_mult = 0;
    mosq->in_packet.packet_length = 0;
    mosq->in_packet.to_process = 0;
    mosq->in_packet.packet_buffer = NULL;
    mosq->in_packet.packet_buffer_pos = 0;
    mosq->in_packet.packet_buffer_size = 0;
    mosq->in_packet.packet_buffer_to_process = 0;
    mosq->in_packet.remaining_count = 0;

    // 3) protocol: choose MQTT v5 to allow exercising reason code & properties parsing.
    mosq->protocol = mosq_p_mqtt5;

    // 4) msgs_out mutex: handle__pubackcomp locks msgs_out.mutex; initialize if present.
#ifdef WITH_THREADING
    // msgs_out is a mosquitto_msg_data which, in non-broker builds, contains a mutex.
    // Initialize it to avoid undefined behavior.
    pthread_mutex_init(&mosq->msgs_out.mutex, NULL);
#endif

    // 5) Other fields: id may be used for logging; provide a small non-null string.
    mosq->id = (char *)malloc(2);
    if (mosq->id){
        mosq->id[0] = '\0';
    }

    // Decide "type" based on the first byte of Data (if available), else default to "pubAck".
    // The implementation checks type[3] == 'A' to select PUBACK behavior.
    const char *type_str = "pubAck";
    if (Size > 0) {
        if ((Data[0] & 1) == 0) {
            type_str = "pubComp";
        } else {
            type_str = "pubAck";
        }
    }

    // Set in_packet.command to match chosen type. The function validates this field.
    if (type_str[3] == 'A') {
        mosq->in_packet.command = CMD_PUBACK;
    } else {
        mosq->in_packet.command = CMD_PUBCOMP;
    }

    // Call the target function. It will operate on the in_packet payload (the fuzzer input).
    // The function will internally call packet__read_uint16/packet__read_byte/property parsing, etc.
    // We ignore the return value: fuzzing should watch for crashes, ASAN reports, etc.
    (void)handle__pubackcomp(mosq, type_str);

    // Clean up.
#ifdef WITH_THREADING
    pthread_mutex_destroy(&mosq->msgs_out.mutex);
    pthread_mutex_destroy(&mosq->state_mutex);
#endif
    if (mosq->id) free(mosq->id);
    free(mosq);

    return 0;
}
