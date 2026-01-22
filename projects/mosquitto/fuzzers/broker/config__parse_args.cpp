#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>

extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Limit number of arguments to a reasonable amount to avoid extreme behavior.
    const size_t kMaxArgs = 32;

    // Prepare a vector of std::string to own the argument storage.
    std::vector<std::string> arg_storage;
    arg_storage.reserve(kMaxArgs);

    // argv[0] is typically program name.
    arg_storage.emplace_back("fuzzer");

    // Turn the input bytes into a sequence of small strings to act as argv entries.
    // We walk the input data and create chunks whose lengths are derived from the bytes.
    size_t idx = 0;
    while (idx < Size && arg_storage.size() < kMaxArgs) {
        // Derive a length in range [1, 16] from the next byte (if available).
        uint8_t control = Data[idx];
        idx++;

        size_t len = (control % 16) + 1;
        if (len > Size - idx) {
            len = Size - idx;
        }

        // Copy bytes to string, but replace any '\0' with 'x' so C string functions
        // used by config__parse_args (strcmp, atoi, etc.) behave sensibly.
        std::string s;
        s.reserve(len + 1);
        for (size_t k = 0; k < len; k++) {
            char c = static_cast<char>(Data[idx + k]);
            if (c == '\0') c = 'x';
            s.push_back(c);
        }
        idx += len;

        // To increase likelihood of hitting interesting code paths, if the generated
        // string contains printable bytes, leave as-is. Otherwise map to a small set
        // of common option tokens using the first byte.
        bool printable = false;
        for (char c : s) {
            if (c >= 32 && c < 127) { printable = true; break; }
        }
        if (!printable) {
            // Map to some common CLI options used by config__parse_args
            switch (control % 8) {
                case 0: s = "-d"; break;
                case 1: s = "-h"; break;
                case 2: s = "-p"; break;
                case 3: s = "--port"; break;
                case 4: s = "-q"; break;
                case 5: s = "-v"; break;
                case 6: s = "--test-config"; break;
                default: s = "--version"; break;
            }
        } else {
            // Additionally sometimes convert the string into a numeric string (for -p)
            if ((control & 0x3) == 0x3) {
                // create small numeric string in range [0, 65540]
                unsigned num = (unsigned)control + (unsigned)(len * 31);
                char buf[16];
                snprintf(buf, sizeof(buf), "%u", num);
                s = buf;
            }
        }

        arg_storage.push_back(std::move(s));
    }

    // Build argv pointers array. We cast away const because the target function expects char* argv[].
    std::vector<char*> argv;
    argv.reserve(arg_storage.size() + 1);
    for (size_t i = 0; i < arg_storage.size(); ++i) {
        // Ensure the string has stable storage and is null-terminated.
        argv.push_back(const_cast<char*>(arg_storage[i].c_str()));
    }

    int argc = static_cast<int>(argv.size());

    // Prepare a mosquitto__config struct and initialize it properly.
    struct mosquitto__config config;
    // Use the project's config initializer to set sane defaults.
    config__init(&config);

    // Remember original db.tls_keylog so we only free what was allocated by this run.
    char *orig_tls_keylog = db.tls_keylog;

    // Call the target function. config__parse_args will process argv and may
    // allocate memory or set pointers into argv contents.
    (void)config__parse_args(&config, argc, argv.empty() ? nullptr : argv.data());

    // Cleanup any allocations owned by the config struct.
    config__cleanup(&config);

    // If config__parse_args allocated a new tls_keylog string in db, free it to avoid leaks.
    if(db.tls_keylog && db.tls_keylog != orig_tls_keylog){
        mosquitto_FREE(db.tls_keylog);
        db.tls_keylog = orig_tls_keylog;
    }

    // Return 0 as required by libFuzzer
    return 0;
}
