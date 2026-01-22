// SPDX-License-Identifier: (same as project)
// Fuzzer harness that uses the project's pw__decode_sha512 implementation.

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>
#include <cstdio>

// Ensure we compile the TLS-enabled body of password_common.c so the real
// pw__decode_sha512 implementation is available.
#define WITH_TLS 1

// Include mosquitto headers first so declarations like
//   void *mosquitto_calloc(size_t nmemb, size_t size);
// are processed without being broken by our macros.
#include "/src/mosquitto/include/mosquitto.h"

// Provide a small C++ allocation wrapper so that calls in the included C source
// that call mosquitto_calloc(...) can be implicitly converted to any pointer
// type in C++ (char*, struct mosquitto_pw*, etc.). This avoids changing the
// upstream C file and avoids invalid conversion from void* to typed pointers
// in C++.
struct mosq_alloc_wrapper {
    void *p;
    mosq_alloc_wrapper(size_t nmemb, size_t size) {
        p = calloc(nmemb, size);
    }
    // Convert to any pointer type implicitly.
    template<typename U>
    operator U*() const { return reinterpret_cast<U*>(p); }
};

// Provide mosquitto_* function macros for the code we include.
// These macros are intentionally simple and map into libc implementations.
// They are only used while compiling password_common.c below.
#define mosquitto_calloc(nmemb, size) mosq_alloc_wrapper((nmemb),(size))
#define mosquitto_free(ptr) free((ptr))
#define mosquitto_strdup(s) strdup((s))

extern "C" {
    // Include the project's password_common.c directly so the static
    // pw__decode_sha512 is compiled into this translation unit.
    //
    // Note: This relies on building inside the project tree and linking
    // with the project's build (OpenSSL, etc.), which is the normal setup
    // for in-tree fuzzers.
    //
    // Adjust path below if necessary for your build environment.
    #include "/src/mosquitto/libcommon/password_common.c"
}

// Undefine the macros so they don't leak into the remainder of this file.
#undef mosquitto_calloc
#undef mosquitto_free
#undef mosquitto_strdup

// Fuzzer entry point expected by LLVM libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!Data) return 0;

    // Prepare mosquitto_pw structure (defined in password_common.c)
    struct mosquitto_pw pw_obj;
    memset(&pw_obj, 0, sizeof(pw_obj));
    pw_obj.encoded_password = NULL;
    pw_obj.valid = false;
    pw_obj.hashtype = MOSQ_PW_SHA512;

    // Convert input bytes to a NUL-terminated string.
    // Replace embedded NULs with 'A' so strtok and other C string funcs behave.
    std::string s;
    s.reserve(Size + 1);
    for (size_t i = 0; i < Size; ++i) {
        unsigned char c = Data[i];
        if (c == 0) s.push_back('A');
        else s.push_back((char)c);
    }
    if (s.empty()) {
        // Provide a non-empty default to exercise parsing code-paths.
        s = "AAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    }
    s.push_back('\0'); // ensure null-terminated

    // Call the real, in-tree static function pw__decode_sha512 compiled into this TU.
    // This function expects the portion after "$6$" (i.e., salt_password),
    // but the function itself will parse the string on "$" boundaries; we pass the
    // raw prepared string to allow the function to exercise its parsing.
    volatile int rc = pw__decode_sha512(&pw_obj, s.c_str());
    (void)rc;

    // Cleanup encoded_password if set by any code-paths (defensive).
    if (pw_obj.encoded_password) {
        free(pw_obj.encoded_password);
        pw_obj.encoded_password = NULL;
    }

    return 0;
}
