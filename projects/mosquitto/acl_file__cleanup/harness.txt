#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <algorithm>

extern "C" {
#include "/src/mosquitto/src/acl_file.h"
}

/*
 Fuzz driver for:
   void acl_file__cleanup(struct acl_file_data * data);

 Strategy:
 - Parse the fuzzer input to construct a small acl_file_data instance.
 - Create a small number of users (uthash) and acl entries (linked lists).
 - Call acl_file__cleanup(data) which should free the internal structures.
 - Finally free any memory not freed by acl_file__cleanup (the acl_file string and the acl_file_data
   struct itself).
 - All reads from the fuzz input are bounds-checked and allocations limited to
   reasonable maxima to avoid huge allocations.
*/

static inline uint8_t read_u8(const uint8_t *data, size_t size, size_t &pos)
{
    if(pos >= size) return 0;
    return data[pos++];
}

static inline size_t take_size_t(const uint8_t *data, size_t size, size_t &pos, size_t max_val)
{
    if(pos >= size) return 0;
    // use one byte to decide length up to max_val (0..max_val)
    uint8_t v = read_u8(data, size, pos);
    return (size_t)(v % (max_val + 1));
}

static char *make_string_from_input(const uint8_t *data, size_t size, size_t &pos, size_t max_len)
{
    size_t remaining = (pos < size ? size - pos : 0);
    if(remaining == 0) {
        // return empty string
        char *s = (char*)malloc(1);
        if(s) s[0] = '\0';
        return s;
    }
    // Consume one byte to decide the string length; make sure to account for this byte
    // so we don't subsequently read past the input buffer.
    uint8_t b = data[pos++];
    // Now compute how many bytes are actually available for the string payload
    size_t avail = (pos < size ? size - pos : 0);
    // Bound by configured max_len as well as actual available bytes.
    size_t allowed_max = std::min(avail, max_len);
    size_t len = 0;
    if(allowed_max > 0) {
        len = (size_t)(b % (allowed_max + 1)); // 0..allowed_max
    } else {
        len = 0;
    }
    char *s = (char*)malloc(len + 1);
    if(!s) return nullptr;
    if(len > 0) {
        memcpy(s, data + pos, len);
        pos += len;
    }
    s[len] = '\0';
    return s;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    size_t pos = 0;

    // Limits to avoid excessive allocations from fuzz input
    const size_t MAX_USERS = 16;
    const size_t MAX_ENTRIES_PER_USER = 32;
    const size_t MAX_PATTERNS = 32;
    const size_t MAX_TOPIC_LEN = 128;
    const size_t MAX_USERNAME_LEN = 64;

    // Create acl_file_data on heap
    struct acl_file_data *data = (struct acl_file_data*)malloc(sizeof(struct acl_file_data));
    if(!data) return 0;
    data->acl_file = nullptr;
    data->acl_users = nullptr;
    data->acl_anon.acl = nullptr;
    data->acl_patterns = nullptr;

    // Optionally create an acl_file string from input
    // Use small max length
    size_t make_file_flag = read_u8(Data, Size, pos) & 1;
    if(make_file_flag && pos < Size) {
        char *f = make_string_from_input(Data, Size, pos, 64);
        data->acl_file = f;
    } else {
        data->acl_file = nullptr;
    }

    // Number of users
    size_t users = take_size_t(Data, Size, pos, MAX_USERS);

    for(size_t ui = 0; ui < users; ui++){
        // allocate user
        struct acl__user *u = (struct acl__user*)malloc(sizeof(struct acl__user));
        if(!u) break;
        u->hh.tbl = nullptr; // not strictly necessary, HASH_ADD will initialize
        u->acl = nullptr;
        // make username
        u->username = make_string_from_input(Data, Size, pos, MAX_USERNAME_LEN);
        if(!u->username){
            free(u);
            break;
        }

        // number of entries for this user
        size_t entries = take_size_t(Data, Size, pos, MAX_ENTRIES_PER_USER);
        struct acl__entry *head = nullptr;
        struct acl__entry *prev = nullptr;
        for(size_t ei = 0; ei < entries; ei++){
            struct acl__entry *e = (struct acl__entry*)malloc(sizeof(struct acl__entry));
            if(!e) break;
            e->next = nullptr;
            e->prev = prev;
            e->access = 0;
            e->ucount = 0;
            e->ccount = 0;
            // make topic string
            e->topic = make_string_from_input(Data, Size, pos, MAX_TOPIC_LEN);
            if(!e->topic){
                free(e);
                break;
            }
            if(prev){
                prev->next = e;
            } else {
                head = e;
            }
            prev = e;
        }
        u->acl = head;

        // Add to hash by username using uthash macro
        // HASH_ADD_STR(head, fieldname, add)
        // data->acl_users is the head pointer
        HASH_ADD_STR(data->acl_users, username, u);
    }

    // Patterns list (global patterns)
    size_t patterns = take_size_t(Data, Size, pos, MAX_PATTERNS);
    struct acl__entry *phead = nullptr;
    struct acl__entry *pprev = nullptr;
    for(size_t pi = 0; pi < patterns; pi++){
        struct acl__entry *pe = (struct acl__entry*)malloc(sizeof(struct acl__entry));
        if(!pe) break;
        pe->next = nullptr;
        pe->prev = pprev;
        pe->access = 0;
        pe->ucount = 0;
        pe->ccount = 0;
        pe->topic = make_string_from_input(Data, Size, pos, MAX_TOPIC_LEN);
        if(!pe->topic){
            free(pe);
            break;
        }
        if(pprev) pprev->next = pe;
        else phead = pe;
        pprev = pe;
    }
    data->acl_patterns = phead;

    // Optionally create anon user's acl entries
    size_t anon_entries = take_size_t(Data, Size, pos, MAX_ENTRIES_PER_USER);
    struct acl__entry *anon_head = nullptr;
    struct acl__entry *anon_prev = nullptr;
    for(size_t ai = 0; ai < anon_entries; ai++){
        struct acl__entry *ae = (struct acl__entry*)malloc(sizeof(struct acl__entry));
        if(!ae) break;
        ae->next = nullptr;
        ae->prev = anon_prev;
        ae->access = 0;
        ae->ucount = 0;
        ae->ccount = 0;
        ae->topic = make_string_from_input(Data, Size, pos, MAX_TOPIC_LEN);
        if(!ae->topic){
            free(ae);
            break;
        }
        if(anon_prev) anon_prev->next = ae;
        else anon_head = ae;
        anon_prev = ae;
    }
    data->acl_anon.acl = anon_head;

    // Call the target function under test
    acl_file__cleanup(data);

    // acl_file__cleanup frees users (and their usernames) and frees entries via acl__free_entries.
    // It also sets data->acl_patterns = NULL and data->acl_anon.acl = NULL.
    // But it doesn't free data->acl_file or the data struct itself. Free them here if still present.

    if(data->acl_file){
        free(data->acl_file);
        data->acl_file = NULL;
    }

    // Free any leftover structures just in case (defensive):
    // Free patterns list if still present
    struct acl__entry *cur = data->acl_patterns;
    while(cur){
        struct acl__entry *nxt = cur->next;
        if(cur->topic) free(cur->topic);
        free(cur);
        cur = nxt;
    }
    data->acl_patterns = nullptr;

    // Free anon list if still present
    cur = data->acl_anon.acl;
    while(cur){
        struct acl__entry *nxt = cur->next;
        if(cur->topic) free(cur->topic);
        free(cur);
        cur = nxt;
    }
    data->acl_anon.acl = nullptr;

    free(data);
    return 0;
}