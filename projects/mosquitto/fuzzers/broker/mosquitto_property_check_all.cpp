#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cassert>

// Minimal mosquitto property definitions used by the harness.
// We avoid including the real libcommon_properties.h which depends on build-specific
// macros (libmosqcommon_EXPORT) and other headers that are not available here.

extern "C" {

// Minimal mqtt__string used by property struct.
struct mqtt__string {
    char *v;
    uint16_t len;
};

// Define the property struct layout matching the project's internal definition
// (mqtt5__property -> mosquitto_property).
struct mqtt5__property {
    struct mqtt5__property *next;
    union {
        uint8_t i8;
        uint16_t i16;
        uint32_t i32;
        uint32_t varint;
        struct mqtt__string bin;
        struct mqtt__string s;
    } value;
    struct mqtt__string name;
    int32_t identifier;
    uint8_t property_type;
    bool client_generated;
};

typedef struct mqtt5__property mosquitto_property;

// Prototype of the fuzz target function we want to exercise.
// The actual implementation is provided by the mosquitto code being tested.
int mosquitto_property_check_all(int command, const mosquitto_property *properties);

} // extern "C"


// Minimal DataReader implementation to safely consume fuzzer input.
class DataReader {
public:
    DataReader(const uint8_t *data, size_t size) : data_(data), size_(size), pos_(0) {}

    bool empty() const { return pos_ >= size_; }

    // Read an unsigned 8-bit integer; return default_val if no data left.
    uint8_t read_u8(uint8_t default_val = 0) {
        if (pos_ + 1 > size_) return default_val;
        return data_[pos_++];
    }

    // Read an unsigned 16-bit integer (little-endian). Return default_val if insufficient data.
    uint16_t read_u16(uint16_t default_val = 0) {
        if (pos_ + 2 > size_) return default_val;
        uint16_t v = (uint16_t)data_[pos_] | ((uint16_t)data_[pos_ + 1] << 8);
        pos_ += 2;
        return v;
    }

    // Read an unsigned 32-bit integer (little-endian). Return default_val if insufficient data.
    uint32_t read_u32(uint32_t default_val = 0) {
        if (pos_ + 4 > size_) return default_val;
        uint32_t v = (uint32_t)data_[pos_] |
                     ((uint32_t)data_[pos_ + 1] << 8) |
                     ((uint32_t)data_[pos_ + 2] << 16) |
                     ((uint32_t)data_[pos_ + 3] << 24);
        pos_ += 4;
        return v;
    }

    // Read a boolean: consume one byte if available; otherwise return default_val.
    bool read_bool(bool default_val = false) {
        if (pos_ + 1 > size_) return default_val;
        return data_[pos_++] & 1;
    }

    // Read up to max_len bytes as a string/buffer. Returns malloc'ed buffer (must be freed by caller).
    // Sets out_len to actual length. If insufficient data, returns nullptr and sets out_len to 0.
    char *read_string_and_alloc(size_t max_len, uint16_t &out_len) {
        out_len = 0;
        if (empty()) return nullptr;

        // Decide a length byte or two from the input. Use up to 2 bytes for length if available.
        // Use available bytes to build a length but cap by max_len and remaining bytes.
        size_t remaining = size_ - pos_;
        if (remaining == 0) return nullptr;

        // Read a 1- or 2-byte length depending on availability: prefer 2 bytes if available.
        uint16_t len = 0;
        if (remaining >= 2) {
            // Use a 16-bit length value (little endian), but cap it.
            len = read_u16(0);
        } else {
            len = read_u8(0);
        }

        if (len == 0) {
            // Treat zero-length string as empty string allocated.
            char *buf = (char *)malloc(1);
            if (!buf) return nullptr;
            buf[0] = '\0';
            out_len = 0;
            return buf;
        }

        if (len > max_len) len = (uint16_t)max_len;
        // Now limit by remaining bytes
        size_t avail = size_ - pos_;
        if (avail == 0) {
            // No bytes left to read the requested string
            return nullptr;
        }
        size_t to_copy = std::min<size_t>(len, avail);

        char *buf = (char *)malloc(to_copy + 1);
        if (!buf) return nullptr;
        memcpy(buf, data_ + pos_, to_copy);
        buf[to_copy] = '\0';
        pos_ += to_copy;
        out_len = (uint16_t)to_copy;
        return buf;
    }

private:
    const uint8_t *data_;
    size_t size_;
    size_t pos_;
};


// The following function fuzzes
//     int mosquitto_property_check_all(int command, const mosquitto_property * properties);
//
// The fuzzer entry point is defined as follows:
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data || Size == 0) return 0;

    DataReader dr(Data, Size);

    // Determine command from first byte(s). Keep it small.
    int command = (int)dr.read_u8(0);

    // Decide how many properties to create (0..max_props). Limit to avoid OOM or huge loops.
    uint8_t count_raw = dr.read_u8(0);
    const unsigned MAX_PROPS = 64;
    unsigned count = std::min<unsigned>((unsigned)count_raw, MAX_PROPS);

    mosquitto_property *head = nullptr;
    mosquitto_property *tail = nullptr;

    for (unsigned i = 0; i < count; ++i) {
        if (dr.empty()) break;

        // Allocate a property node
        mosquitto_property *p = (mosquitto_property*)calloc(1, sizeof(mosquitto_property));
        if (!p) break;

        // Initialize fields to safe defaults (calloc already zeroes memory)
        p->next = nullptr;
        p->client_generated = false;

        // identifier: read 32-bit (may map to MQTT_PROP_* constants)
        p->identifier = (int32_t)dr.read_u32(0);

        // property_type: synthesize a small range value to cover types commonly used by the code.
        // We map an input byte into one of several known types:
        // 0: BYTE, 1: INT16, 2: INT32, 3: VARINT, 4: STRING, 5: BINARY, 6: STRING_PAIR
        uint8_t pt = dr.read_u8(0) % 7;
        p->property_type = pt;

        // client_generated flag
        p->client_generated = dr.read_bool(false);

        // Fill value depending on chosen property_type.
        // Use small caps for lengths to avoid allocating huge buffers from fuzz input.
        const size_t MAX_ALLOC_STR = 2048;

        switch (pt) {
            case 0: // BYTE
                p->value.i8 = dr.read_u8(0);
                break;
            case 1: // INT16
                p->value.i16 = dr.read_u16(0);
                break;
            case 2: // INT32
                p->value.i32 = dr.read_u32(0);
                break;
            case 3: // VARINT
                p->value.varint = dr.read_u32(0);
                break;
            case 4: { // STRING
                uint16_t slen = 0;
                char *s = dr.read_string_and_alloc(MAX_ALLOC_STR, slen);
                if (s) {
                    p->value.s.v = s;
                    p->value.s.len = slen;
                } else {
                    p->value.s.v = nullptr;
                    p->value.s.len = 0;
                }
                break;
            }
            case 5: { // BINARY
                uint16_t blen = 0;
                char *b = dr.read_string_and_alloc(MAX_ALLOC_STR, blen);
                if (b) {
                    p->value.bin.v = b;
                    p->value.bin.len = blen;
                } else {
                    p->value.bin.v = nullptr;
                    p->value.bin.len = 0;
                }
                break;
            }
            case 6: { // STRING_PAIR: name + value
                uint16_t nlen = 0;
                char *n = dr.read_string_and_alloc(256, nlen); // name limit smaller
                if (n) {
                    p->name.v = n;
                    p->name.len = nlen;
                } else {
                    p->name.v = nullptr;
                    p->name.len = 0;
                }
                uint16_t vlen = 0;
                char *v = dr.read_string_and_alloc(MAX_ALLOC_STR, vlen);
                if (v) {
                    p->value.s.v = v;
                    p->value.s.len = vlen;
                } else {
                    p->value.s.v = nullptr;
                    p->value.s.len = 0;
                }
                break;
            }
            default:
                // Shouldn't reach; fallback to zeroed values.
                break;
        }

        // IMPORTANT: Clear pointer fields for property types that do not store pointers.
        // This avoids interpreting numeric union fields (i8/i16/i32/varint) as pointers
        // later in the mosquitto code when a property identifier expects a string.
        if (pt != 4 && pt != 5 && pt != 6) {
            // Zero the union pointer interpretation and any name field.
            p->value.s.v = nullptr;
            p->value.s.len = 0;
            // Also clear bin view for completeness (shares union memory).
            p->value.bin.v = nullptr;
            p->value.bin.len = 0;
            // Clear name in case it was left non-zero (calloc already zeroes, but keep explicit).
            p->name.v = nullptr;
            p->name.len = 0;
        }

        // Append to linked list
        if (!head) {
            head = p;
            tail = p;
        } else {
            tail->next = p;
            tail = p;
        }
    }

    // Call the target function with the constructed list.
    // We capture the return value and mix it with a checksum of the input into a volatile sink
    // so the compiler cannot optimize away the call or the dependence on the input bytes.
    static volatile int fuzz_sink = 0;
    int rv = mosquitto_property_check_all(command, head);

    // Compute a simple checksum over the input so the behavior depends on the fuzzer data.
    uint32_t checksum = 0x811C9DC5u; // FNV offset basis
    for (size_t i = 0; i < Size; ++i) {
        checksum ^= Data[i];
        checksum *= 16777619u; // FNV prime
    }
    // Mix return value and checksum into sink (volatile) so optimizer keeps everything.
    fuzz_sink ^= rv ^ (int)(checksum & 0xFFFFFFFFu);

    // Free all allocated memory we created.
    mosquitto_property *cur = head;
    while (cur) {
        mosquitto_property *next = cur->next;
        // Free strings/binary we allocated based on property_type / name
        // Note: mqtt__string stores a char* v and uint16_t len.
        switch (cur->property_type) {
            case 4: // STRING
                if (cur->value.s.v) free(cur->value.s.v);
                break;
            case 5: // BINARY
                if (cur->value.bin.v) free(cur->value.bin.v);
                break;
            case 6: // STRING_PAIR
                if (cur->name.v) free(cur->name.v);
                if (cur->value.s.v) free(cur->value.s.v);
                break;
            default:
                // numeric types require no freeing
                break;
        }

        free(cur);
        cur = next;
    }

    // Use the volatile sink in a no-op way to avoid compiler removing it entirely.
    // (This has no semantic effect on the target code; it just prevents over-aggressive optimization.)
    if (fuzz_sink == 0xDEADBEEF) {
        // unreachable in practice, but uses fuzz_sink value
        abort();
    }

    return 0;
}