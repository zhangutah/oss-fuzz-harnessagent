// Fixed harness for mosquitto_pw_hash_encoded fuzzing.
// Changes made:
// - Ensure the fuzz input bytes are actually used by the target call even if the input contains '\0' bytes.
//   The previous memcpy produced a C string that could be terminated early causing most inputs to be ignored.
//   Now we map input bytes so the produced NUL-terminated password never contains internal NULs.
// - Use both the first and last input bytes (when present) to select the hash type to increase exercised paths.
// - Keep the required function signature unchanged.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif

enum mosquitto_pwhash_type {
    MOSQ_PW_DEFAULT,
    MOSQ_PW_SHA512 = 6,
    MOSQ_PW_SHA512_PBKDF2 = 7,
    MOSQ_PW_ARGON2ID = 8,
};

struct mosquitto_pw;

/* Declarations provided by the mosquitto library at link time. */
int mosquitto_pw_new(struct mosquitto_pw **pw, enum mosquitto_pwhash_type hashtype);
void mosquitto_pw_cleanup(struct mosquitto_pw *pw);
int mosquitto_pw_hash_encoded(struct mosquitto_pw *pw, const char *password);

#ifdef __cplusplus
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Data == nullptr) return 0;

    // Allocate Size + 1 bytes to ensure termination.
    char *password = (char *)malloc(Size + 1);
    if (!password) return 0;

    // Build a NUL-terminated password string from the input bytes, but avoid any internal NULs.
    // If we memcpy raw bytes and the input contains a '\0', the C string will be truncated and
    // most of the fuzz input will be unused. Map bytes so every byte becomes a non-zero char.
    // We keep a deterministic, 1:1 mapping in length.
    for (size_t i = 0; i < Size; ++i) {
        uint8_t b = Data[i];
        // Map zero to 1, otherwise keep the byte as-is. Cast to char.
        // Avoid producing a NUL anywhere in the string.
        password[i] = (char)(b == 0 ? 1 : b);
    }
    password[Size] = '\0';

    // Choose a hash type based on the first and last byte of input (if present) to exercise different code paths.
    int type_map[4] = {
        MOSQ_PW_DEFAULT,        // 0
        MOSQ_PW_SHA512,         // 6
        MOSQ_PW_SHA512_PBKDF2,  // 7
        MOSQ_PW_ARGON2ID        // 8
    };

    int sel = 0;
    if (Size > 0) {
        sel = Data[0] % 4;
        // Mix in the last byte when available to vary selection more across inputs.
        if (Size > 1) {
            sel = (sel + (Data[Size - 1] % 4)) % 4;
        }
    }
    enum mosquitto_pwhash_type chosen_type = (enum mosquitto_pwhash_type)type_map[sel];

    // Allocate and initialize mosquitto_pw structure.
    struct mosquitto_pw *pw = nullptr;
    int rc_new = mosquitto_pw_new(&pw, chosen_type);
    if (rc_new != 0 || pw == nullptr) {
        // Failed to create pw object; clean up and return.
        free(password);
        return 0;
    }

    // Call the target function with the fuzzed password. Use the full (non-truncated) password.
    (void)mosquitto_pw_hash_encoded(pw, password);

    // Clean up allocated resources.
    mosquitto_pw_cleanup(pw);
    free(password);

    return 0;
}
