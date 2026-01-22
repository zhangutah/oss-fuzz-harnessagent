#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <new>
#include <atomic>

// Include the property definition so mosquitto_property is a complete type.
#include "/src/mosquitto/libcommon/property_common.h"

extern "C" {

// Include the real implementation from the project so we call the actual
// plugin__handle_message_single implementation instead of a fake one.
//
// Relative path from this harness to the project source file:
#include "../../src/plugin_message.c"

} // extern "C"

// Harness-specific callback userdata and callback implementation

struct CBData {
	const uint8_t *buf;
	size_t buf_len;
	size_t pos;
	int ret_code; // 0 for success, non-zero to cause plugin handler to break
	bool change_topic;
	bool change_payload;
	bool change_properties;
	size_t topic_len;
	size_t payload_len;
	size_t max_alloc; // cap allocations to avoid blowing memory
};

static size_t read_len_from_buf(const uint8_t *buf, size_t buf_len, size_t &pos, size_t cap)
{
	if(pos >= buf_len) return 0;
	size_t v = buf[pos++] % (cap + 1);
	return v;
}

extern "C" int test_cb(int ev_type, void *event, void *userdata)
{
	if(!event) return MOSQ_ERR_SUCCESS;
	mosquitto_evt_message *e = (mosquitto_evt_message *)event;
	CBData *d = (CBData *)userdata;
	if(!d) return MOSQ_ERR_SUCCESS;
	if(d->ret_code != 0) return d->ret_code;

	// Possibly change topic
	if(d->change_topic){
		size_t len = d->topic_len;
		if(len > d->max_alloc) len = d->max_alloc;
		char *s = (char *)malloc(len + 1);
		if(s){
			// Fill with pseudo-data from buffer
			for(size_t i=0;i<len;i++){
				uint8_t v = 0;
				if(d->pos < d->buf_len) v = d->buf[d->pos++];
				s[i] = (char)(32 + (v % 95)); // printable range
			}
			s[len] = '\0';
			// assign new topic pointer
			e->topic = s;
		}
	}

	// Possibly change payload
	if(d->change_payload){
		size_t len = d->payload_len;
		if(len > d->max_alloc) len = d->max_alloc;
		void *p = nullptr;
		if(len){
			p = malloc(len);
			if(p){
				for(size_t i=0;i<len;i++){
					uint8_t v = 0;
					if(d->pos < d->buf_len) v = d->buf[d->pos++];
					((uint8_t*)p)[i] = v;
				}
			}
		}
		e->payload = p;
		e->payloadlen = (uint32_t)len;
	}

	// Possibly change properties (create a single property element)
	if(d->change_properties){
		mosquitto_property *mp = (mosquitto_property *)malloc(sizeof(mosquitto_property));
		if(mp){
			mp->next = nullptr;
		}
		e->properties = mp;
	}

	return MOSQ_ERR_SUCCESS;
}

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	if(!Data || Size == 0) return 0;

	// Keep parsing simple and safe
	size_t pos = 0;
	auto read_u8 = [&](uint8_t &out)->bool {
		if(pos >= Size) { out = 0; return false; }
		out = Data[pos++]; return true;
	};

	// 1) number of callbacks (0..3)
	uint8_t tmp;
	read_u8(tmp);
	unsigned num_callbacks = (tmp % 4);

	// 2) event type (in/out)
	read_u8(tmp);
	enum mosquitto_plugin_event ev_type = (tmp % 2) ? MOSQ_EVT_MESSAGE_OUT : MOSQ_EVT_MESSAGE_IN;

	// 3) to_free initial flags
	read_u8(tmp);
	bool tf_topic = (tmp & 0x1);
	bool tf_payload = (tmp & 0x2);
	bool tf_properties = (tmp & 0x4);

	// 4) initial stored topic length and allocation
	size_t init_topic_len = read_len_from_buf(Data, Size, pos, 64);
	char *init_topic = nullptr;
	if(init_topic_len){
		init_topic = (char*)malloc(init_topic_len + 1);
		if(init_topic){
			for(size_t i=0;i<init_topic_len;i++){
				uint8_t v = 0;
				if(pos < Size) v = Data[pos++];
				init_topic[i] = (char)(32 + (v % 95));
			}
			init_topic[init_topic_len] = '\0';
		}
	}

	// 5) initial payloadlen and payload allocation
	size_t init_payload_len = read_len_from_buf(Data, Size, pos, 256);
	void *init_payload = nullptr;
	if(init_payload_len){
		init_payload = malloc(init_payload_len);
		if(init_payload){
			for(size_t i=0;i<init_payload_len;i++){
				uint8_t v = 0;
				if(pos < Size) v = Data[pos++];
				((uint8_t*)init_payload)[i] = v;
			}
		}
	}

	// 6) initial properties flag (create or not)
	bool init_has_properties = false;
	if(pos < Size){
		init_has_properties = (Data[pos++] & 1);
	}
	mosquitto_property *init_properties = nullptr;
	if(init_has_properties){
		init_properties = (mosquitto_property*)malloc(sizeof(mosquitto_property));
		if(init_properties) init_properties->next = nullptr;
	}

	// 7) initial qos and retain
	uint8_t init_qos = 0;
	read_u8(init_qos);
	bool init_retain = false;
	read_u8(tmp);
	init_retain = (tmp & 1);

	// Build stored message (use project's mosquitto_base_msg)
	mosquitto_base_msg stored;
	memset(&stored, 0, sizeof(stored));
	stored.topic = init_topic;
	stored.payload = init_payload;
	stored.payloadlen = (uint32_t)init_payload_len;
	stored.properties = init_properties;
	stored.qos = init_qos;
	stored.retain = init_retain;

	// Build should_free (use project's should_free)
	should_free sf;
	sf.topic = tf_topic;
	sf.payload = tf_payload;
	sf.properties = tf_properties;

	// Build callbacks list (use project's mosquitto__callback)
	mosquitto__callback *callbacks = nullptr;
	mosquitto__callback *last = nullptr;
	CBData **userdata_arr = nullptr;
	if(num_callbacks){
		userdata_arr = (CBData**)malloc(sizeof(CBData*) * num_callbacks);
		if(!userdata_arr){
			// fallback: zero out
			num_callbacks = 0;
		}
	}
	for(unsigned i=0;i<num_callbacks;i++){
		mosquitto__callback *cb = (mosquitto__callback*)malloc(sizeof(mosquitto__callback));
		if(!cb) break;
		memset(cb, 0, sizeof(*cb));
		// Parse callback-specific parameters from remaining data
		CBData *ud = (CBData*)malloc(sizeof(CBData));
		if(!ud){
			free(cb);
			break;
		}
		ud->buf = Data;
		ud->buf_len = Size;
		ud->pos = pos;
		ud->ret_code = 0;
		// decide whether this callback will change topic/payload/properties
		uint8_t flags = 0;
		if(pos < Size) flags = Data[pos++];
		ud->change_topic = (flags & 1);
		ud->change_payload = (flags & 2);
		ud->change_properties = (flags & 4);
		ud->topic_len = read_len_from_buf(Data, Size, pos, 64);
		ud->payload_len = read_len_from_buf(Data, Size, pos, 512);
		ud->max_alloc = 1024; // safe cap
		// Optionally make this callback return non-zero to break chain
		if(pos < Size){
			ud->ret_code = (Data[pos++] & 1) ? 1 : 0;
		}

		// update pos back into ud for later use by callback
		ud->pos = pos;

		// store userdata and callback
		userdata_arr[i] = ud;
		cb->cb = test_cb;
		cb->userdata = ud;
		cb->next = nullptr;
		cb->prev = last;
		if(last) last->next = cb;
		last = cb;
		if(!callbacks) callbacks = cb;

		// sync pos to ud->pos (some bytes may have been consumed already by reading lengths)
		pos = ud->pos;
	}

	// Prepare a trivial mosquitto context pointer (use project's mosquitto)
	mosquitto ctx;
	memset(&ctx, 0, sizeof(ctx));

	// Save original pointers so we can free them if they get replaced but not freed by the plugin.
	char *orig_topic = stored.topic;
	void *orig_payload = stored.payload;
	mosquitto_property *orig_properties = stored.properties;

	// Call the target function from the project
	(void)plugin__handle_message_single(callbacks, ev_type, &sf, &ctx, &stored);

	// If the plugin replaced stored.* but did not free the original (because
	// the initial to_free flag was false), free the original ourselves to
	// avoid leaks.
	if(orig_topic && orig_topic != stored.topic && !tf_topic){
		free(orig_topic);
		orig_topic = nullptr;
	}
	if(orig_payload && orig_payload != stored.payload && !tf_payload){
		free(orig_payload);
		orig_payload = nullptr;
	}
	if(orig_properties && orig_properties != stored.properties && !tf_properties){
		// free the original properties list allocated by the harness
		mosquitto_property_free_all(&orig_properties);
		orig_properties = nullptr;
	}

	// Cleanup: free stored fields if still present (not freed by function)
	if(stored.topic){
		free(stored.topic);
		stored.topic = nullptr;
	}
	if(stored.payload){
		free(stored.payload);
		stored.payload = nullptr;
	}
	if(stored.properties){
		// use project's mosquitto_property_free_all
		mosquitto_property_free_all(&stored.properties);
	}

	// Free callback userdata and callback nodes
	if(userdata_arr){
		for(unsigned i=0;i<num_callbacks;i++){
			if(userdata_arr[i]) free(userdata_arr[i]);
		}
		free(userdata_arr);
	}
	// Free callbacks themselves
	mosquitto__callback *it = callbacks;
	while(it){
		mosquitto__callback *next = it->next;
		free(it);
		it = next;
	}

	return 0;
}
