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
// // int handle__publish(struct mosquitto *context)
// //{
// //	uint8_t dup;
// //	int rc = 0;
// //	uint8_t header = context->in_packet.command;
// //	struct mosquitto__base_msg *base_msg;
// //	size_t len;
// //	uint16_t slen;
// //	char *topic_mount;
// //	mosquitto_property *properties = NULL;
// //	uint32_t message_expiry_interval = MSG_EXPIRY_INFINITE;
// //	int topic_alias = -1;
// //	uint16_t mid = 0;
// //
// //	if(context->state != mosq_cs_active){
// //		return MOSQ_ERR_PROTOCOL;
// //	}
// //
// //	context->stats.messages_received++;
// //
// //	base_msg = mosquitto_calloc(1, sizeof(struct mosquitto__base_msg));
// //	if(base_msg == NULL){
// //		return MOSQ_ERR_NOMEM;
// //	}
// //
// //	dup = (header & 0x08)>>3;
// //	base_msg->data.qos = (header & 0x06)>>1;
// //	if(dup == 1 && base_msg->data.qos == 0){
// //		log__printf(NULL, MOSQ_LOG_INFO,
// //				"Invalid PUBLISH (QoS=0 and DUP=1) from %s, disconnecting.", context->id);
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_MALFORMED_PACKET;
// //	}
// //	if(base_msg->data.qos == 3){
// //		log__printf(NULL, MOSQ_LOG_INFO,
// //				"Invalid QoS in PUBLISH from %s, disconnecting.", context->id);
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_MALFORMED_PACKET;
// //	}
// //	if(base_msg->data.qos > context->max_qos){
// //		log__printf(NULL, MOSQ_LOG_INFO,
// //				"Too high QoS in PUBLISH from %s, disconnecting.", context->id);
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_QOS_NOT_SUPPORTED;
// //	}
// //	base_msg->data.retain = (header & 0x01);
// //
// //	if(base_msg->data.retain && db.config->retain_available == false){
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_RETAIN_NOT_SUPPORTED;
// //	}
// //
// //	if(packet__read_string(&context->in_packet, &base_msg->data.topic, &slen)){
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_MALFORMED_PACKET;
// //	}
// //	if(!slen && context->protocol != mosq_p_mqtt5){
// //		/* Invalid publish topic, disconnect client. */
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_MALFORMED_PACKET;
// //	}
// //
// //	if(base_msg->data.qos > 0){
// //		if(packet__read_uint16(&context->in_packet, &mid)){
// //			db__msg_store_free(base_msg);
// //			return MOSQ_ERR_MALFORMED_PACKET;
// //		}
// //		if(mid == 0){
// //			db__msg_store_free(base_msg);
// //			return MOSQ_ERR_PROTOCOL;
// //		}
// //		/* It is important to have a separate copy of mid, because msg may be
// //		 * freed before we want to send a PUBACK/PUBREC. */
// //		base_msg->data.source_mid = mid;
// //	}
// //
// //	/* Handle properties */
// //	if(context->protocol == mosq_p_mqtt5){
// //		rc = property__read_all(CMD_PUBLISH, &context->in_packet, &properties);
// //		if(rc){
// //			db__msg_store_free(base_msg);
// //			return rc;
// //		}
// //
// //		rc = property__process_publish(base_msg, &properties, &topic_alias, &message_expiry_interval, context->bridge);
// //		if(rc){
// //			mosquitto_property_free_all(&properties);
// //			db__msg_store_free(base_msg);
// //			return MOSQ_ERR_PROTOCOL;
// //		}
// //	}
// //	mosquitto_property_free_all(&properties);
// //
// //	if(topic_alias == 0 || (context->listener && topic_alias > context->listener->max_topic_alias)){
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_TOPIC_ALIAS_INVALID;
// //	}else if(topic_alias > 0){
// //		if(base_msg->data.topic){
// //			rc = alias__add_r2l(context, base_msg->data.topic, (uint16_t)topic_alias);
// //			if(rc){
// //				db__msg_store_free(base_msg);
// //				return rc;
// //			}
// //		}else{
// //			rc = alias__find_by_alias(context, ALIAS_DIR_R2L, (uint16_t)topic_alias, &base_msg->data.topic);
// //			if(rc){
// //				db__msg_store_free(base_msg);
// //				return MOSQ_ERR_PROTOCOL;
// //			}
// //		}
// //	}
// //
// //#ifdef WITH_BRIDGE
// //	rc = bridge__remap_topic_in(context, &base_msg->data.topic);
// //	if(rc){
// //		db__msg_store_free(base_msg);
// //		return rc;
// //	}
// //
// //#endif
// //	if(mosquitto_pub_topic_check(base_msg->data.topic) != MOSQ_ERR_SUCCESS){
// //		/* Invalid publish topic, just swallow it. */
// //		db__msg_store_free(base_msg);
// //		return MOSQ_ERR_MALFORMED_PACKET;
// //	}
// //
// //	base_msg->data.payloadlen = context->in_packet.remaining_length - context->in_packet.pos;
// //	metrics__int_inc(mosq_counter_pub_bytes_received, base_msg->data.payloadlen);
// //	if(context->listener && context->listener->mount_point){
// //		len = strlen(context->listener->mount_point) + strlen(base_msg->data.topic) + 1;
// //		topic_mount = mosquitto_malloc(len+1);
// //		if(!topic_mount){
// //			db__msg_store_free(base_msg);
// //			return MOSQ_ERR_NOMEM;
// //		}
// //		snprintf(topic_mount, len, "%s%s", context->listener->mount_point, base_msg->data.topic);
// //		topic_mount[len] = '\0';
// //
// //		mosquitto_FREE(base_msg->data.topic);
// //		base_msg->data.topic = topic_mount;
// //	}
// //
// //	if(base_msg->data.payloadlen){
// //		if(db.config->message_size_limit && base_msg->data.payloadlen > db.config->message_size_limit){
// //			log__printf(NULL, MOSQ_LOG_DEBUG, "Dropped too large PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic, (long)base_msg->data.payloadlen);
// //			return process_bad_message(context, base_msg, MQTT_RC_PACKET_TOO_LARGE);
// //		}
// //		base_msg->data.payload = mosquitto_malloc(base_msg->data.payloadlen+1);
// //		if(base_msg->data.payload == NULL){
// //			db__msg_store_free(base_msg);
// //			return MOSQ_ERR_NOMEM;
// //		}
// //		/* Ensure payload is always zero terminated, this is the reason for the extra byte above */
// //		((uint8_t *)base_msg->data.payload)[base_msg->data.payloadlen] = 0;
// //
// //		if(packet__read_bytes(&context->in_packet, base_msg->data.payload, base_msg->data.payloadlen)){
// //			db__msg_store_free(base_msg);
// //			return MOSQ_ERR_MALFORMED_PACKET;
// //		}
// //	}
// //
// //	/* Check for topic access */
// //	rc = mosquitto_acl_check(context, base_msg->data.topic, base_msg->data.payloadlen, base_msg->data.payload, base_msg->data.qos, base_msg->data.retain, MOSQ_ACL_WRITE);
// //	if(rc == MOSQ_ERR_ACL_DENIED){
// //		log__printf(NULL, MOSQ_LOG_DEBUG,
// //				"Denied PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))",
// //				context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic,
// //				(long)base_msg->data.payloadlen);
// //		return process_bad_message(context, base_msg, MQTT_RC_NOT_AUTHORIZED);
// //	}else if(rc != MOSQ_ERR_SUCCESS){
// //		db__msg_store_free(base_msg);
// //		return rc;
// //	}
// //
// //	log__printf(NULL, MOSQ_LOG_DEBUG, "Received PUBLISH from %s (d%d, q%d, r%d, m%d, '%s', ... (%ld bytes))", context->id, dup, base_msg->data.qos, base_msg->data.retain, base_msg->data.source_mid, base_msg->data.topic, (long)base_msg->data.payloadlen);
// //
// //	if(!strncmp(base_msg->data.topic, "$CONTROL/", 9)){
// //#ifdef WITH_CONTROL
// //		rc = control__process(context, base_msg);
// //		db__msg_store_free(base_msg);
// //		return rc;
// //#else
// //		return process_bad_message(context, base_msg, MQTT_RC_IMPLEMENTATION_SPECIFIC);
// //#endif
// //	}
// //
// //	return handle__accepted_publish(context, base_msg, mid, dup, &message_expiry_interval);
// //}
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     int property__process_publish(struct mosquitto__base_msg * base_msg, mosquitto_property ** props, int * topic_alias, uint32_t * message_expiry_interval, _Bool is_bridge);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
// Fuzz driver for property__process_publish
//
// Builds a linked list of mosquitto_property objects from the fuzzer input
// and calls property__process_publish. Attempts to free allocated memory
// after the call. This driver uses absolute project headers discovered
// from the workspace.

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <new>

extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/libcommon/property_common.h"
#include "/src/mosquitto/include/mosquitto/mqtt_protocol.h"
}

// Helper: allocate a mosquitto_property with zeroed memory.
static mosquitto_property *alloc_property()
{
    mosquitto_property *p = (mosquitto_property *)calloc(1, sizeof(mosquitto_property));
    return p;
}

// Helper: safe read of little-endian 16-bit and 32-bit values from buffer
static uint16_t read_u16_le(const uint8_t *Data, size_t Size, size_t pos)
{
    uint16_t v = 0;
    if(pos < Size) v |= Data[pos];
    if(pos + 1 < Size) v |= ((uint16_t)Data[pos + 1]) << 8;
    return v;
}
static uint32_t read_u32_le(const uint8_t *Data, size_t Size, size_t pos)
{
    uint32_t v = 0;
    for(int i=0;i<4;i++){
        if(pos + (size_t)i < Size) v |= ((uint32_t)Data[pos + i]) << (8*i);
    }
    return v;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Prepare a mosquitto__base_msg on the heap and zero it.
    struct mosquitto__base_msg *base_msg = (mosquitto__base_msg *)calloc(1, sizeof(struct mosquitto__base_msg));
    if(!base_msg) return 0;
    // Ensure inner data is zeroed.
    memset(&base_msg->data, 0, sizeof(base_msg->data));

    // We'll create properties based on input bytes.
    // Map input bytes into a set of identifiers that property__process_publish understands.
    const int id_choices[] = {
        MQTT_PROP_CONTENT_TYPE,             // string
        MQTT_PROP_CORRELATION_DATA,         // binary
        MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, // byte
        MQTT_PROP_RESPONSE_TOPIC,           // string
        MQTT_PROP_USER_PROPERTY,            // string pair
        MQTT_PROP_TOPIC_ALIAS,              // int16
        MQTT_PROP_MESSAGE_EXPIRY_INTERVAL,  // int32
        MQTT_PROP_SUBSCRIPTION_IDENTIFIER   // varint
    };
    const size_t id_count = sizeof(id_choices)/sizeof(id_choices[0]);

    std::vector<mosquitto_property*> all_props;
    mosquitto_property *head = NULL;
    mosquitto_property *last = NULL;

    // Limit number of properties to avoid huge allocations.
    size_t max_props = 64;
    size_t pos = 0;
    size_t created = 0;

    while(pos < Size && created < max_props){
        // Choose which identifier to use based on next byte.
        uint8_t sel = Data[pos++];
        int id = id_choices[sel % id_count];

        mosquitto_property *p = alloc_property();
        if(!p) break;

        p->identifier = id;
        p->client_generated = false;
        p->next = NULL;

        // Fill value depending on identifier.
        switch(id){
            case MQTT_PROP_TOPIC_ALIAS:
                // int16
                p->property_type = MQTT_PROP_TYPE_INT16;
                // Need 2 bytes for value
                {
                    uint16_t v = 0;
                    if(pos < Size){
                        v = read_u16_le(Data, Size, pos);
                        pos += (pos + 1 < Size) ? 2 : 1;
                    }
                    p->value.i16 = v;
                }
                break;
            case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
                // int32
                p->property_type = MQTT_PROP_TYPE_INT32;
                {
                    uint32_t v = read_u32_le(Data, Size, pos);
                    // advance up to 4 bytes
                    size_t adv = 0;
                    for(; adv < 4 && pos + adv < Size; ++adv);
                    pos += adv;
                    p->value.i32 = v;
                }
                break;
            case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
                // varint (we'll store as varint in i32 union)
                p->property_type = MQTT_PROP_TYPE_VARINT;
                {
                    // read up to 4 bytes for varint style
                    uint32_t v = 0;
                    if(pos < Size){
                        v = Data[pos++];
                        if(pos < Size){ v |= ((uint32_t)Data[pos++] << 8); }
                        if(pos < Size){ v |= ((uint32_t)Data[pos++] << 16); }
                        if(pos < Size){ v |= ((uint32_t)Data[pos++] << 24); }
                    }
                    p->value.varint = v;
                }
                break;
            case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
                // byte
                p->property_type = MQTT_PROP_TYPE_BYTE;
                if(pos < Size){
                    p->value.i8 = Data[pos++];
                }else{
                    p->value.i8 = 0;
                }
                break;
            case MQTT_PROP_CORRELATION_DATA:
                // binary - use mqtt__string.bin
                p->property_type = MQTT_PROP_TYPE_BINARY;
                {
                    // choose length from next byte
                    size_t len = 0;
                    if(pos < Size){
                        len = Data[pos++] % 16; // keep small
                    }
                    if(len){
                        char *buf = (char *)malloc(len + 1);
                        if(buf){
                            for(size_t i=0;i<len && pos < Size;i++){
                                buf[i] = (char)Data[pos++];
                            }
                            // zero-pad remainder if not enough input
                            if(pos >= Size){
                                // fill remaining with zero
                                for(size_t i=0;i<len;i++){
                                    // already filled partial; safe to leave rest zero
                                    if(i >= len) break;
                                }
                            }
                            buf[len] = '\0';
                            p->value.bin.v = buf;
                            p->value.bin.len = (uint16_t)len;
                        }else{
                            p->value.bin.v = NULL;
                            p->value.bin.len = 0;
                        }
                    }else{
                        p->value.bin.v = NULL;
                        p->value.bin.len = 0;
                    }
                }
                break;
            case MQTT_PROP_CONTENT_TYPE:
            case MQTT_PROP_RESPONSE_TOPIC:
                // string
                p->property_type = MQTT_PROP_TYPE_STRING;
                {
                    size_t len = 0;
                    if(pos < Size){
                        len = Data[pos++] % 16;
                    }
                    if(len){
                        char *s = (char *)malloc(len + 1);
                        if(s){
                            for(size_t i=0;i<len && pos < Size;i++){
                                s[i] = (char)Data[pos++];
                            }
                            s[len] = '\0';
                            p->value.s.v = s;
                            p->value.s.len = (uint16_t)len;
                        }else{
                            p->value.s.v = NULL;
                            p->value.s.len = 0;
                        }
                    }else{
                        p->value.s.v = NULL;
                        p->value.s.len = 0;
                    }
                }
                break;
            case MQTT_PROP_USER_PROPERTY:
                // string pair (we'll set name as first string, and value as second via value.s)
                p->property_type = MQTT_PROP_TYPE_STRING_PAIR;
                {
                    // For property_common representation, the struct has name (string) and value.s for value.
                    // We'll allocate small name and value from data.
                    size_t nlen = 0;
                    if(pos < Size) nlen = Data[pos++] % 8;
                    if(nlen){
                        char *nv = (char *)malloc(nlen + 1);
                        if(nv){
                            for(size_t i=0;i<nlen && pos < Size;i++){
                                nv[i] = (char)Data[pos++];
                            }
                            nv[nlen] = '\0';
                            p->name.v = nv;
                            p->name.len = (uint16_t)nlen;
                        }else{
                            p->name.v = NULL;
                            p->name.len = 0;
                        }
                    }else{
                        p->name.v = NULL;
                        p->name.len = 0;
                    }
                    size_t vlen = 0;
                    if(pos < Size) vlen = Data[pos++] % 8;
                    if(vlen){
                        char *vv = (char *)malloc(vlen + 1);
                        if(vv){
                            for(size_t i=0;i<vlen && pos < Size;i++){
                                vv[i] = (char)Data[pos++];
                            }
                            vv[vlen] = '\0';
                            p->value.s.v = vv;
                            p->value.s.len = (uint16_t)vlen;
                        }else{
                            p->value.s.v = NULL;
                            p->value.s.len = 0;
                        }
                    }else{
                        p->value.s.v = NULL;
                        p->value.s.len = 0;
                    }
                }
                break;
            default:
                // Unknown/other: set as string with zero length.
                p->property_type = MQTT_PROP_TYPE_STRING;
                p->value.s.v = NULL;
                p->value.s.len = 0;
                break;
        }

        // Link into list
        if(!head){
            head = p;
            last = p;
        }else{
            last->next = p;
            last = p;
        }
        all_props.push_back(p);
        ++created;
    }

    // Prepare variables for call
    mosquitto_property *prop_list = head;
    int topic_alias = -1;
    uint32_t message_expiry_interval = 0;
    bool is_bridge = false;
    // Use one more input byte if available to set is_bridge
    if(pos < Size){
        is_bridge = (Data[pos++] & 1) != 0;
    }

    // Call the function under test.
    // property__process_publish may alter the props pointer and move nodes into base_msg->data.properties.
    property__process_publish(base_msg, &prop_list, &topic_alias, &message_expiry_interval, is_bridge ? true : false);

    // Clean up: free all allocated memory we created.
    // Note: properties may be moved into base_msg->data.properties, but pointers remain identical.
    for(mosquitto_property *p : all_props){
        if(!p) continue;
        // Free any allocated strings/binary we created.
        // Based on property_type, free appropriate fields.
        if(p->property_type == MQTT_PROP_TYPE_STRING || p->property_type == MQTT_PROP_TYPE_STRING_PAIR){
            // If value.s.v was allocated, free it.
            if(p->value.s.v){
                free((void*)p->value.s.v);
                p->value.s.v = NULL;
            }
            // Name may also be used for string pair:
            if(p->name.v){
                free((void*)p->name.v);
                p->name.v = NULL;
            }
        }else if(p->property_type == MQTT_PROP_TYPE_BINARY){
            if(p->value.bin.v){
                free((void*)p->value.bin.v);
                p->value.bin.v = NULL;
            }
        }
        // Finally free the property struct itself.
        free(p);
    }
    all_props.clear();

    // If base_msg->data properties were used internally and nodes moved, we've already freed them above
    // because they were the same pointers. Clear pointer to avoid dangling pointer.
    base_msg->data.properties = NULL;

    // Free base_msg
    free(base_msg);

    return 0;
}
