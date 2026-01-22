#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <memory>
#include <limits>

extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/libcommon/property_common.h"
}

/*
 * Fuzzer harness for property__process_will.
 *
 * Builds a linked list of mosquitto_property (mqtt5__property) nodes from input bytes,
 * then calls the real property__process_will from the project.
 *
 * The per-node format (variable length, parsed from remaining bytes):
 *  - 1 byte: identifier selector (mapped to known property ids or an unknown id)
 *  - Up to 4 bytes: int32 / i32 value
 *  - Up to 2 bytes: int16 / i16 value
 *  - Up to 4 bytes: varint value
 *
 * If not enough bytes remain for a field, the field is left as 0.
 */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    std::vector<mosquitto_property*> nodes;
    nodes.reserve(32);

    size_t pos = 0;
    while(pos < Size){
        mosquitto_property *node = (mosquitto_property*)calloc(1, sizeof(mosquitto_property));
        if(!node) break;
        node->next = nullptr;

        // Identifier mapping: map input byte to either one of the known properties or an unknown one.
        uint8_t sel = Data[pos++];
        uint32_t id;
        switch(sel % 12){ // include some values that will trigger default case
            case 0: id = MQTT_PROP_CONTENT_TYPE; break;
            case 1: id = MQTT_PROP_CORRELATION_DATA; break;
            case 2: id = MQTT_PROP_PAYLOAD_FORMAT_INDICATOR; break;
            case 3: id = MQTT_PROP_RESPONSE_TOPIC; break;
            case 4: id = MQTT_PROP_USER_PROPERTY; break;
            case 5: id = MQTT_PROP_WILL_DELAY_INTERVAL; break;
            case 6: id = MQTT_PROP_MESSAGE_EXPIRY_INTERVAL; break;
            default: id = 0xABCDEFu; break; // unknown property id -> default path
        }
        node->identifier = (int32_t)id;

        // int32_value: take up to 4 bytes -> store in union i32
        uint32_t v32 = 0;
        for(int i=0;i<4 && pos < Size;i++){
            v32 = (v32 << 8) | Data[pos++];
        }
        node->value.i32 = v32;

        // int16_value: up to 2 bytes -> store in union i16
        uint16_t v16 = 0;
        for(int i=0;i<2 && pos < Size;i++){
            v16 = (v16 << 8) | Data[pos++];
        }
        node->value.i16 = v16;

        // varint_value: up to 4 bytes -> store in union varint
        uint32_t vv = 0;
        for(int i=0;i<4 && pos < Size;i++){
            vv = (vv << 8) | Data[pos++];
        }
        node->value.varint = vv;

        nodes.push_back(node);
    }

    // Link nodes into a single list
    mosquitto_property *props_head = nullptr;
    mosquitto_property *tail = nullptr;
    for(auto n : nodes){
        if(!props_head){
            props_head = n;
            tail = n;
        }else{
            tail->next = n;
            tail = n;
        }
    }
    if(tail) tail->next = nullptr;

    // Prepare context and message using real project structs (zeroed)
    struct mosquitto *ctx = (struct mosquitto*)calloc(1, sizeof(struct mosquitto));
    struct mosquitto_message_all *msg = (struct mosquitto_message_all*)calloc(1, sizeof(struct mosquitto_message_all));
    if(!ctx || !msg){
        // cleanup allocations and exit
        for(auto n : nodes) free(n);
        free(ctx);
        free(msg);
        return 0;
    }
    ctx->will_delay_interval = 0;
    msg->expiry_interval = 0;
    msg->properties = nullptr;

    // Call target function from project
    mosquitto_property *props_ptr = props_head;
    (void)property__process_will(ctx, msg, &props_ptr);

    // Clean up: free all remaining property nodes.
    // property__process_will moves some nodes from props to msg->properties;
    // to avoid double-free traverse both lists and free nodes once.
    std::vector<mosquitto_property*> freed;
    freed.reserve(nodes.size());

    auto free_list = [&](mosquitto_property *p){
        while(p){
            bool already = false;
            for(auto fp : freed){
                if(fp == p){ already = true; break; }
            }
            if(already) break;
            freed.push_back(p);
            mosquitto_property *next = p->next;
            free(p);
            p = next;
        }
    };

    free_list(props_ptr);
    free_list(msg->properties);

    // In case any nodes were not reachable from props_ptr or msg->properties (defensive), free them.
    for(auto n : nodes){
        bool was = false;
        for(auto f : freed){
            if(f == n){ was = true; break; }
        }
        if(!was){
            free(n);
        }
    }

    free(ctx);
    free(msg);

    return 0;
}
