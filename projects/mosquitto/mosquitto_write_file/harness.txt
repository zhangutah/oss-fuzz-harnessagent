#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <atomic>
#include <limits.h>
#include <unistd.h>
#include <stdarg.h> // for va_list used in the included C header

// Some project headers declare libmosqcommon_EXPORT; define it as empty here
// if it isn't defined so the header compiles in this harness build.
#ifndef libmosqcommon_EXPORT
#define libmosqcommon_EXPORT
#endif

// Include the project header for mosquitto_write_file (absolute path as found).
#include "/src/mosquitto/include/mosquitto/libcommon_file.h"

// Simple user data structure to pass the fuzzer input to the write callback.
// Add a control byte so the write callback can choose behavior based on fuzzer data.
struct WriteUserData {
    const uint8_t *data;
    size_t size;
    uint8_t control; // control byte derived from the first fuzzer byte
};

// write_fn signature: int (*write_fn)(FILE *fptr, void *user_data)
static int fuzz_write_fn(FILE *fptr, void *user_data)
{
    if(!fptr || !user_data) return 1; // non-zero for failure

    WriteUserData *ud = static_cast<WriteUserData*>(user_data);

    // If no payload, consider success (mosquitto_write_file treats 0 as success).
    if(ud->size == 0) {
        return 0;
    }

    uint8_t mode = ud->control & 0x03; // 0..3

    switch(mode){
        case 0: {
            // Write the entire buffer in one fwrite call.
            size_t written = fwrite(ud->data, 1, ud->size, fptr);
            if(written != ud->size) {
                return 1;
            }
            break;
        }
        case 1: {
            // Write byte-by-byte using fputc to exercise per-byte writes.
            for(size_t i=0; i<ud->size; ++i){
                if(fputc(ud->data[i], fptr) == EOF){
                    return 1;
                }
            }
            break;
        }
        case 2: {
            // Write only a prefix of the buffer (half), exercising partial-content cases.
            size_t write_len = ud->size / 2;
            if(write_len == 0) write_len = 1; // ensure we write something if size>0
            size_t written = fwrite(ud->data, 1, write_len, fptr);
            if(written != write_len){
                return 1;
            }
            break;
        }
        case 3: {
            // Force an error from the write callback to hit mosquitto_write_file error path.
            return 1;
        }
        default:
            return 1;
    }

    // Flush to increase chance of filesystem interactions.
    if(fflush(fptr) != 0) {
        return 1;
    }

    return 0; // MOSQ_ERR_SUCCESS is 0 in upstream mosquitto
}

// log_fn signature: void (*log_fn)(const char *msg)
static void fuzz_log_fn(const char *msg)
{
    // Keep logging minimal for fuzz runs; do not call heavy functions.
    (void)msg;
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr || Size == 0) {
        return 0;
    }

    // Use the first byte as a control byte; the rest is payload.
    uint8_t control = Data[0];
    const uint8_t *payload = nullptr;
    size_t payload_size = 0;
    if(Size > 1){
        payload = Data + 1;
        payload_size = Size - 1;
    }else{
        payload = nullptr;
        payload_size = 0;
    }

    // Create a stable unique-ish target path per invocation to avoid races.
    // Use an atomic counter so repeated calls in the same process get different names.
    static std::atomic<unsigned long> counter{0};
    unsigned long id = ++counter;

    char target_path[PATH_MAX];
    int rc = snprintf(target_path, sizeof(target_path), "/tmp/mosq_fuzz_%lu", id);
    if(rc < 0 || rc >= (int)sizeof(target_path)) {
        // If the path couldn't be created, bail out.
        return 0;
    }

    // Prepare user data for the write callback.
    WriteUserData ud;
    ud.data = payload;
    ud.size = payload_size;
    ud.control = control;

    // Determine restrict_read from a bit in the control byte so behavior varies.
    bool restrict_read = (control & 0x01) != 0;

    // Call mosquitto_write_file. mosquitto_write_file will create a tmp file "<target>.new" and call our write_fn.
    (void)mosquitto_write_file(target_path, restrict_read, &fuzz_write_fn, &ud, &fuzz_log_fn);

    // Attempt to clean up files possibly left behind. Ignore errors.
    // The function creates "<target>.new" and may leave the original target file.
    char tmp_path[PATH_MAX];
    if(snprintf(tmp_path, sizeof(tmp_path), "%s.new", target_path) >= 0) {
        unlink(tmp_path);
    }
    unlink(target_path);

    return 0;
}
