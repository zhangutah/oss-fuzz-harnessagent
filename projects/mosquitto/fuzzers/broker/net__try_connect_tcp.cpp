#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <algorithm>

// Include OpenSSL's header first so its prototype for SSL_get_ex_data
// is processed before we introduce our call-site redirect macro.
// Put it inside an extern "C" to ensure proper linkage when compiled as C++.
extern "C" {
#include <openssl/ssl.h>
}

extern "C" {
// Forward declare the mosquitto struct so the wrapper can return its pointer type.
struct mosquitto;
}

// Provide a C-linkage wrapper that returns a struct mosquitto * (casts the void*).
// This will be called from the net_mosq.c translation unit via the macro below.
extern "C" struct mosquitto *SSL_get_ex_data_mosq(const SSL *ssl, int idx) {
    // Call the real OpenSSL function (declared in <openssl/ssl.h>) and cast.
    return (struct mosquitto *)SSL_get_ex_data(ssl, idx);
}

// Redirect SSL_get_ex_data function CALLS inside the included C file to the wrapper.
// Because we included <openssl/ssl.h> above, the header's prototype will not be
// affected by this macro (include guards prevent reprocessing).
#define SSL_get_ex_data(ssl, idx) SSL_get_ex_data_mosq(ssl, idx)

// Avoid _GNU_SOURCE macro redefinition errors when including the C file.
// If _GNU_SOURCE is already defined by the compiler, undefine it here so the
// #define _GNU_SOURCE in net_mosq.c can apply without triggering a redefinition warning/error.
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

// Include the C translation unit which contains the static function.
// This allows calling static functions from that C file (net__try_connect_tcp is static).
extern "C" {
#include "/src/mosquitto/lib/net_mosq.c"
}

// Undo our macro redefinition to avoid affecting other compilation units.
#undef SSL_get_ex_data

// Helper: turn arbitrary bytes into a small printable hostname-like string.
// This reduces surprising non-printable input for getaddrinfo.
static std::string bytes_to_printable(const uint8_t *data, size_t len) {
    if (len == 0) return std::string("localhost");
    std::string s;
    s.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        // Map to a-z, digits or dot to make it resemble a host name
        uint8_t r = b % 38;
        if (r < 26) {
            s.push_back(char('a' + r));
        } else if (r < 36) {
            s.push_back(char('0' + (r - 26)));
        } else {
            s.push_back('.');
        }
    }
    // Ensure no leading/trailing dot
    if (!s.empty() && s.front() == '.') s.front() = 'a';
    if (!s.empty() && s.back() == '.') s.back() = 'a';
    return s;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == nullptr || Size == 0) return 0;

    size_t pos = 0;

    // First byte: flags. bit0 = use_bind_address
    bool use_bind = (Data[pos] & 0x1) != 0;
    pos++;

    // Next two bytes: port (little-endian). If not enough bytes, default 1883.
    uint16_t port = 1883;
    if (pos + 2 <= Size) {
        port = (uint16_t)Data[pos] | ((uint16_t)Data[pos + 1] << 8);
        pos += 2;
    }

    // Next byte: blocking flag (0 or non-zero). If not present, default false.
    bool blocking = false;
    if (pos < Size) {
        blocking = (Data[pos] & 0x1) != 0;
        pos++;
    }

    // Remaining bytes: host and optionally bind_address.
    size_t remaining = (pos < Size) ? (Size - pos) : 0;
    std::string host_str, bind_str;
    if (remaining == 0) {
        host_str = "localhost";
    } else {
        if (use_bind && remaining >= 2) {
            // split remaining roughly in half
            size_t host_len = remaining / 2;
            size_t bind_len = remaining - host_len;
            host_str = bytes_to_printable(Data + pos, host_len);
            bind_str = bytes_to_printable(Data + pos + host_len, bind_len);
        } else {
            // all remaining bytes -> host
            host_str = bytes_to_printable(Data + pos, remaining);
        }
    }

    // Prepare parameters
    const char *host_c = host_str.c_str();
    const char *bind_c = use_bind ? bind_str.c_str() : NULL;

    // Call the target function.
    mosq_sock_t sock = INVALID_SOCKET;
    // net__try_connect_tcp is defined static in the included C file so we can call it directly.
    // The function may perform network operations; the fuzzer environment should handle that.
    (void)net__try_connect_tcp(host_c, port, &sock, bind_c, blocking ? 1 : 0);

    // Clean up any open socket left by the function to avoid resource leaks between fuzz runs.
    if (sock != INVALID_SOCKET) {
        COMPAT_CLOSE(sock);
        sock = INVALID_SOCKET;
    }

    return 0;
}