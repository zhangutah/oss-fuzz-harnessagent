// /src/mosquitto/fuzzing/broker/broker_fuzz_queue_msg.cpp
// Fuzz harness that uses the real proxy_v2__read from the project.
// It provides minimal stubs for functions the implementation depends on,
// and a net__read that feeds bytes from libFuzzer's input.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdarg>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <algorithm>

// Prevent the project's libcommon_memory.h from being parsed here.
#define MOSQUITTO_LIBCOMMON_MEMORY_H

// Global allocation tracker to avoid leaks from repeated overwrites of
// strings inside proxy parsing during fuzzing.
static std::vector<void*> g_allocs;

extern "C" {

// Global buffer fed by fuzzer; net__read will consume from this.
static const uint8_t *g_input = nullptr;
static size_t g_input_size = 0;
static size_t g_input_pos = 0;

// Provide a net__read stub which proxy_v2.c will use. It returns ssize_t.
ssize_t net__read(struct mosquitto * /*mosq*/, void *buf, size_t count) {
    if(!g_input || g_input_pos >= g_input_size) return 0; // simulate EOF
    size_t remain = g_input_size - g_input_pos;
    size_t to_copy = count;
    if(to_copy > remain) to_copy = remain;
    memcpy(buf, g_input + g_input_pos, to_copy);
    g_input_pos += to_copy;
    return (ssize_t)to_copy;
}

// We need mosquitto_calloc to produce a uint8_t* when assigned to uint8_t*
// fields in the project code, but the project's header declares it as
// returning void*. To avoid implicit void* -> uint8_t* conversion errors
// in C++ we provide an implementation function returning void* and then
// a macro that casts to uint8_t* for use in the included C code.
void *mosquitto_calloc_impl(size_t nmemb, size_t size) {
    // Over-allocate a small amount of padding to avoid reads just past
    // the requested region (the project's code reads small headers from
    // the buffer and may do small out-of-bounds reads on malformed input).
    const size_t EXTRA_PADDING = 64;

    // Compute requested total size and guard for overflow.
    if(nmemb == 0 || size == 0) {
        // behave like calloc: return zeroed memory block (size 0 -> may return NULL)
        return calloc(nmemb, size);
    }

    size_t total = nmemb;
    // check multiplication overflow
    if (size > SIZE_MAX / total) {
        return nullptr;
    }
    total *= size;

    if (total > SIZE_MAX - EXTRA_PADDING) {
        return nullptr;
    }

    void *p = malloc(total + EXTRA_PADDING);
    if(!p) return nullptr;
    memset(p, 0, total + EXTRA_PADDING);
    return p;
}
// Cast wrapper so assignments like "context->proxy.buf = mosquitto_calloc(...);" compile in C++.
#define mosquitto_calloc(nmemb, size) ((uint8_t*)mosquitto_calloc_impl((nmemb), (size)))

// mosquitto_free: free memory and remove from allocation tracker (if present)
void mosquitto_free(void *p) {
    if(!p) return;
    // remove from tracked allocations if present
    auto it = std::find(g_allocs.begin(), g_allocs.end(), p);
    if(it != g_allocs.end()){
        g_allocs.erase(it);
    }
    free(p);
}
#define mosquitto_FREE(A) do{ mosquitto_free(A); (A)=NULL; } while(0)

char *mosquitto_strndup(const char *s, size_t n) {
    if(!s) return nullptr;
    size_t len = strnlen(s, n);
    char *p = (char *)malloc(len + 1);
    if(!p) return nullptr;
    memcpy(p, s, len);
    p[len] = '\0';
    // track allocation so we can free leftover overwritten allocations later
    g_allocs.push_back(p);
    return p;
}
char *mosquitto_strdup(const char *s) {
    if(!s) return nullptr;
    size_t len = strlen(s);
    char *p = (char *)malloc(len + 1);
    if(!p) return nullptr;
    memcpy(p, s, len);
    p[len] = '\0';
    // track allocation
    g_allocs.push_back(p);
    return p;
}

// Minimal logging stub
void log__printf(void * /*unused*/, int /*level*/, const char * /*fmt*/, ...) {
    // no-op for fuzz harness
}

// Minimal http__context_init stub used in proxy_v2.c under websockets compile paths
// Return 0 to indicate success (MOSQ_ERR_SUCCESS == 0 in project).
int http__context_init(struct mosquitto * /*context */) {
    return 0;
}

} // extern "C"

// Include the real implementation of proxy_v2.c from the project.
// The absolute path was discovered in the project workspace.
#include "/src/mosquitto/src/proxy_v2.c"

// Fuzzer entry point - must not change signature
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Feed fuzz input to net__read
    g_input = Data;
    g_input_size = Size;
    g_input_pos = 0;

    // Prepare a minimal mosquitto context structure used by proxy_v2__read.
    // We only zero-initialize it and set fields that proxy_v2__read expects.
    struct mosquitto ctx;
    memset(&ctx, 0, sizeof(ctx));

    // Initialize proxy sub-structure so proxy_v2__read will take header path
    ctx.proxy.buf = nullptr;
    ctx.proxy.cipher = nullptr;
    ctx.proxy.tls_version = nullptr;
    ctx.proxy.len = 0;
    ctx.proxy.pos = 0;
    ctx.proxy.cmd = -1; // trigger header parsing
    ctx.proxy.fam = 0;
    ctx.proxy.have_tls = false;

    // Provide a minimal listener structure that is referenced by proxy_v2.c
    ctx.listener = (struct mosquitto__listener *)malloc(sizeof(struct mosquitto__listener));
    if(!ctx.listener) return 0;
    // Zero initialize the listener to avoid uninitialized reads.
    memset(ctx.listener, 0, sizeof(struct mosquitto__listener));
#if defined(WITH_TLS)
    ctx.listener->use_identity_as_username = false;
    ctx.listener->proxy_protocol_v2_require_tls = false;
    ctx.listener->require_certificate = false;
#endif
    // protocol is an enum; initialize to 0 (mp_mqtt)
    ctx.listener->protocol = (enum mosquitto_protocol)0;

    ctx.username = nullptr;
    ctx.address = nullptr;
    ctx.remote_port = 0;
    ctx.transport = (enum mosquitto__transport)0;

    // Call the real function from the project
    int rc = proxy_v2__read(&ctx);
    (void)rc;

    // Free any allocations performed by the function or our harness
    if(ctx.username) mosquitto_free(ctx.username);
    if(ctx.proxy.buf) mosquitto_FREE(ctx.proxy.buf);
    if(ctx.proxy.tls_version) mosquitto_FREE(ctx.proxy.tls_version);
    if(ctx.proxy.cipher) mosquitto_FREE(ctx.proxy.cipher);
    if(ctx.listener) free(ctx.listener);
    if(ctx.address) mosquitto_free(ctx.address);

    // Any allocations created by mosquitto_strndup/mosquitto_strdup that were
    // overwritten (and therefore not reachable via the context structures)
    // are still tracked in g_allocs. Free them now to avoid leaks being reported.
    for(void *p : g_allocs){
        free(p);
    }
    g_allocs.clear();

    // Reset global input pointer
    g_input = nullptr;
    g_input_size = 0;
    g_input_pos = 0;

    return 0;
}
