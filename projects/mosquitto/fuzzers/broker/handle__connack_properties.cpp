#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

// Include project headers / source that contain the function under test.
// NOTE: Keep the same path as your build environment provides. Adjust if needed.
extern "C" {
#include "/src/mosquitto/src/handle_connack.c"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Basic sanity checks
    if(!Data || Size == 0){
        return 0;
    }

    // Allocate and zero-initialize a mosquitto context. Use calloc so
    // nested structs are zeroed.
    struct mosquitto *context = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
    if(!context){
        return 0;
    }

    // Copy fuzzer input into a buffer that will simulate the incoming packet payload.
    uint8_t *payload = (uint8_t *)malloc(Size);
    if(!payload){
        free(context);
        return 0;
    }
    memcpy(payload, Data, Size);

    // Initialize the incoming packet to point to our fuzz data.
    context->in_packet.payload = payload;
    context->in_packet.remaining_length = (uint32_t)Size;
    context->in_packet.packet_length = (uint32_t)Size;
    context->in_packet.to_process = (uint32_t)Size;
    context->in_packet.pos = 0;
    context->in_packet.remaining_mult = 1;
    context->in_packet.packet_buffer = NULL;
    context->in_packet.command = CMD_CONNACK; // as used by property parsing in context

    // Initialize other context fields used by handle__connack_properties to
    // reasonable defaults to avoid uninitialised memory dereferences.
    context->msgs_out.inflight_maximum = 10;
    context->maximum_packet_size = 0;
    context->max_qos = 255;
    context->retain_available = 1;
    context->protocol = mosq_p_mqtt5;

    // IMPORTANT FIX:
    // handle__connack_properties may access context->bridge->max_topic_alias.
    // Ensure bridge pointer is valid and has a reasonable max_topic_alias.
    // (The mosquitto build used for fuzzing includes the bridge member.)
    context->bridge = (struct mosquitto__bridge *)calloc(1, sizeof(struct mosquitto__bridge));
    if(!context->bridge){
        free(payload);
        free(context);
        return 0;
    }
    // Provide a safe large default for max_topic_alias so comparisons in
    // handle__connack_properties don't dereference invalid memory.
    context->bridge->max_topic_alias = (uint16_t)65535u;

    // Call the function under test.
    // handle__connack_properties is defined as static in the included C file,
    // so it is available in this TU after including the .c file above.
    (void)handle__connack_properties(context);

    // Clean up. The function under test may allocate properties internally and
    // is expected to free them; free the payload, bridge and context to avoid leaks
    // in the fuzzer harness.
    free(payload);
    free(context->bridge);
    free(context);

    return 0;
}
