// Fuzz driver for:
//   int control__register_callback(mosquitto_plugin_id_t * pid,
//                                  MOSQ_FUNC_generic_callback cb_func,
//                                  const char * topic,
//                                  void * userdata);
// Fuzzer entry point: LLVMFuzzerTestOneInput
//
// Notes:
// - Includes the broker internal header inside extern "C" so we can access types and ensure C linkage.
// - Does NOT provide duplicate definitions for functions implemented by the broker (e.g. control__register_callback).
// - Initializes global `db.config` (declared in the broker headers) to point to an allocated
//   config with cleared security options so HASH macros work with a NULL base.
// - Attempts to register and then unregister to avoid leaking hashed entries across fuzzer iterations.

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <string>

// Include the internal header that declares control__register_callback and the
// types used by it. Wrap in extern "C" so the declarations have C linkage and
// match the C implementations in the project.
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

// Provide a trivial generic callback to pass as cb_func. It matches the
// signature typedef: typedef int (*MOSQ_FUNC_generic_callback)(int, void *, void *);
int fuzz_generic_callback(int event, void *event_data, void *userdata)
{
    (void)event;
    (void)event_data;
    (void)userdata;
    // Return success/status code; exact semantics don't matter for fuzzing.
    return 0;
}

// Helper: sanitize bytes into a printable, null-terminated topic string.
// control__register_callback expects a C string; arbitrary bytes may include NULs.
// We'll turn the input into printable ASCII to make behavior deterministic.
static char *make_topic_from_data(const uint8_t *Data, size_t Size)
{
    if(Size == 0) return nullptr;

    // Cap topic length to a reasonable upper bound.
    const size_t CAP = 65535; // enforce the function's upper bound
    size_t n = (Size > CAP) ? CAP : Size;

    char *buf = (char *)malloc(n + 1);
    if(!buf) return nullptr;

    for(size_t i = 0; i < n; ++i){
        uint8_t b = Data[i];
        // Map to printable ASCII range 0x20..0x7e
        if(b < 0x20) b = 0x20 + (b % 0x5f);
        if(b > 0x7e) b = 0x20 + (b % 0x5f);
        buf[i] = (char)b;
    }
    buf[n] = '\0';

    return buf;
}

// LLVMFuzzerTestOneInput entrypoint
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Defensive checks.
    if(Data == nullptr || Size == 0){
        return 0;
    }

    // Ensure the global db.config and nested security_options/plugin_callbacks are allocated
    // and zero-initialized so the HASH_* macros see a NULL initial hash root.
    // Note: db is provided by the broker libraries via the included header; we just ensure db.config is set.
    if(db.config == nullptr){
        db.config = (struct mosquitto__config *)mosquitto_calloc(1, sizeof(struct mosquitto__config));
        if(db.config == nullptr){
            return 0;
        }
        // plugin_callbacks is zeroed by calloc; plugin_callbacks.control == NULL.
    }

    // Build topic from Data. The fuzzer will mutate Data and the topic will reflect that.
    char *topic = make_topic_from_data(Data, Size);
    // If topic creation failed, bail.
    if(topic == nullptr){
        return 0;
    }

    // Construct a plugin id struct on the stack (zeroed).
    mosquitto_plugin_id_t pid_inst;
    memset(&pid_inst, 0, sizeof(pid_inst));

    // Decide whether plugin_name is set. Use a deterministic decision derived from data:
    // if first byte low bit set, set plugin_name to a strdup of "fuzz_plugin".
    if(Size > 0 && (Data[0] & 1)){
        // Use the broker-provided mosquitto_strdup (do not reimplement it to avoid conflicts).
        pid_inst.plugin_name = mosquitto_strdup("fuzz_plugin");
    }else{
        pid_inst.plugin_name = nullptr;
    }

    // Ensure control_endpoints is NULL initially so DL_APPEND in control__register_callback
    // works as expected.
    pid_inst.control_endpoints = nullptr;

    // userdata can be any pointer; pass nullptr for simplicity.
    void *userdata = nullptr;

    // cb_func: use our trivial callback pointer or occasionally pass NULL to drive invalid path.
    MOSQ_FUNC_generic_callback cb = fuzz_generic_callback;
    if(Size > 1 && (Data[1] == 0xFF)){
        // special case: let fuzzer force NULL callback to trigger the early-return invalid path
        cb = nullptr;
    }

    // Call the function under test. This will use the real implementation from the project.
    int rc = control__register_callback(&pid_inst, cb, topic, userdata);

    // If registration succeeded, attempt to unregister to clean up the hash and endpoints.
    // This helps keep memory usage bounded across many fuzzer iterations in the same process.
    if(rc == MOSQ_ERR_SUCCESS && cb != nullptr){
        // Try to remove the callback. Ignore the result.
        control__unregister_callback(&pid_inst, cb, topic);
    }

    // Free any allocated plugin_name in pid_inst
    if(pid_inst.plugin_name){
        mosquitto_free(pid_inst.plugin_name);
        pid_inst.plugin_name = nullptr;
    }

    // Free allocated topic
    free(topic);

    // Note: We do not free db.config here so that subsequent fuzzer iterations reuse it.
    // If desired, one could free and reset db.config when the fuzzer exits, but that's
    // outside the scope of LLVMFuzzerTestOneInput.

    return 0;
}
