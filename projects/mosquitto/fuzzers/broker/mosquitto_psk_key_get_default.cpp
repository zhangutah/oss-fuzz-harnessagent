#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <cstdlib>
#include <cassert>
#include <string.h> // for strdup
#include <unistd.h>

extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

// Helper: create a heap-allocated C string from input bytes, mapping to printable ASCII and stopping at first 0.
static char *make_cstring_from_slice(const uint8_t *data, size_t len)
{
    if(len == 0){
        char *s = (char *)malloc(1);
        if(s) s[0] = '\0';
        return s;
    }
    std::string tmp;
    tmp.reserve(len + 1);
    for(size_t i=0;i<len;i++){
        uint8_t b = data[i];
        if(b == 0) break;
        if(b < 32 || b > 126){
            b = 32 + (b % 95);
        }
        tmp.push_back(static_cast<char>(b));
    }
    char *s = (char *)malloc(tmp.size() + 1);
    if(!s) return nullptr;
    memcpy(s, tmp.data(), tmp.size());
    s[tmp.size()] = '\0';
    return s;
}

// The fuzzer entry point must keep this signature.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Setup a minimal config and db for each input to avoid cross-run state.
    static mosquitto__config static_config;
    // zero-init relevant fields
    memset(&static_config, 0, sizeof(static_config));
    static_config.per_listener_settings = false;
    static_config.security_options.psk_id = nullptr;
    db.config = &static_config;

    // Interpret the input:
    // Byte 0: flags:
    //  bit 0: per_listener_settings -> if set, function looks in context->listener->security_options
    //  bit 1: populate_psk -> if set, we add psk entries
    //  bit 2: include_matching -> add a PSK whose username equals identity
    uint8_t flags = Data[0];
    bool per_listener_settings = (flags & 0x1) != 0;
    bool populate_psk = (flags & 0x2) != 0;
    bool include_matching = (flags & 0x4) != 0;

    db.config->per_listener_settings = per_listener_settings;

    // Split remaining data into hint / identity / password slices
    const uint8_t *ptr = Data + 1;
    size_t rem = (Size > 1) ? (Size - 1) : 0;

    size_t hint_len = rem / 3;
    size_t identity_len = rem / 3;
    size_t pwd_len = rem - hint_len - identity_len;

    if(rem > 0 && hint_len == 0) hint_len = 1;
    if(rem > hint_len && identity_len == 0) identity_len = 1;
    if(hint_len + identity_len > rem) identity_len = rem - hint_len;
    pwd_len = rem - hint_len - identity_len;

    const uint8_t *hint_ptr = ptr;
    const uint8_t *identity_ptr = ptr + hint_len;
    const uint8_t *pwd_ptr = ptr + hint_len + identity_len;

    char *hint = make_cstring_from_slice(hint_ptr, hint_len);
    char *identity = make_cstring_from_slice(identity_ptr, identity_len);
    char *pwd = make_cstring_from_slice(pwd_ptr, pwd_len);

    // Prepare context and listener structures
    mosquitto ctx_obj;
    mosquitto__listener listener_obj;
    mosquitto__security_options listener_sec;

    // Fully zero init these objects to avoid uninitialized memory reads
    memset(&ctx_obj, 0, sizeof(ctx_obj));
    memset(&listener_obj, 0, sizeof(listener_obj));
    memset(&listener_sec, 0, sizeof(listener_sec));
    listener_sec.psk_id = nullptr;
    listener_obj.security_options = &listener_sec;
    ctx_obj.listener = per_listener_settings ? &listener_obj : nullptr;

    // Build PSK hash list compatible with uthash/struct mosquitto__psk in the project
    mosquitto__psk *psk_head = nullptr;

    if(populate_psk){
        // Entry 1: maybe matching identity
        if(include_matching){
            mosquitto__psk *p = (mosquitto__psk*)calloc(1, sizeof(mosquitto__psk));
            if(p){
                p->username = identity ? strdup(identity) : strdup("");
                if(pwd && pwd[0] != '\0'){
                    p->password = strdup(pwd);
                }else{
                    p->password = strdup("psk_default");
                }
                // Add to hash (key is username)
                HASH_ADD_KEYPTR(hh, psk_head, p->username, (unsigned)strlen(p->username), p);
            }
        }

        // Entry 2: another non-matching entry
        if(rem > 0){
            mosquitto__psk *p2 = (mosquitto__psk*)calloc(1, sizeof(mosquitto__psk));
            if(p2){
                // username from a small derived string to avoid collision
                std::string uname = "user_";
                uname.push_back(static_cast<char>('a' + ((Data[0] >> 3) & 0x1f)));
                p2->username = strdup(uname.c_str());
                p2->password = strdup("password123");
                HASH_ADD_KEYPTR(hh, psk_head, p2->username, (unsigned)strlen(p2->username), p2);
            }
        }
    }

    // Assign psk list to correct place
    if(per_listener_settings){
        if(populate_psk){
            listener_sec.psk_id = psk_head;
        }else{
            listener_sec.psk_id = nullptr;
        }
    }else{
        if(populate_psk){
            static_config.security_options.psk_id = psk_head;
        }else{
            static_config.security_options.psk_id = nullptr;
        }
    }

    // Prepare the key buffer
    int max_key_len = 32;
    if(rem > 0){
        max_key_len = 1 + (Data[Size-1] % 128); // 1..128
    }
    std::vector<char> keybuf((size_t)std::max(1, max_key_len) + 1);
    memset(keybuf.data(), 0, keybuf.size());

    // Call the real target function from the project
    int rc = mosquitto_psk_key_get_default(&ctx_obj, hint, identity, keybuf.data(), max_key_len);

    // Basic sanity-check on success case
    if(rc == MOSQ_ERR_SUCCESS){
        keybuf.back() = '\0';
        size_t klen = strnlen(keybuf.data(), (size_t)max_key_len);
        (void)klen;
    }

    // Cleanup hint/identity/pwd
    if(hint) free(hint);
    if(identity) free(identity);
    if(pwd) free(pwd);

    // Free psk list using uthash iteration macros
    if(populate_psk){
        mosquitto__psk *cur, *tmp;
        mosquitto__psk **psk_loc = per_listener_settings ? &listener_sec.psk_id : &static_config.security_options.psk_id;
        mosquitto__psk *head = *psk_loc;
        HASH_ITER(hh, head, cur, tmp){
            HASH_DEL(head, cur);
            if(cur->username) free(cur->username);
            if(cur->password) free(cur->password);
            free(cur);
        }
        *psk_loc = nullptr;
    }

    (void)rc; // silence unused warning
    return 0;
}
