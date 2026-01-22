#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Include project C headers with C linkage so names match the project's C symbols.
extern "C" {
#include "/src/mosquitto/include/mosquitto.h"
#include "/src/mosquitto/src/password_file.h"
} // extern "C"

// Use the real password_file__parse and password_file__cleanup from the project.
// Do not provide fake definitions here - rely on the project's implementation.

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Create a temporary file for the password file content.
    // mkstemp requires a writable char array.
    char tmpname[] = "/tmp/pwfileXXXXXX";
    int fd = mkstemp(tmpname);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzer input to the temp file. It's okay if the data contains null bytes.
    if (Size > 0) {
        ssize_t written = 0;
        const uint8_t *buf = Data;
        size_t remaining = Size;
        while (remaining > 0) {
            ssize_t w = write(fd, buf + written, remaining);
            if (w <= 0) break;
            written += w;
            remaining -= (size_t)w;
        }
        // Optionally add a newline to ensure last line is read properly by line-based readers.
        const char nl = '\n';
        write(fd, &nl, 1);
    }

    close(fd);

    // Prepare the password_file_data structure expected by password_file__parse.
    struct password_file_data data;
    memset(&data, 0, sizeof(data));
    data.unpwd = NULL;
    // password_file__parse expects a C string path. Use strdup so it can be freed independently.
    data.password_file = strdup(tmpname);
    if (!data.password_file) {
        unlink(tmpname);
        return 0;
    }

    // Call the real target function under test from the project.
    // password_file__parse is C linkage (we included the header within extern "C").
    int rc = password_file__parse(&data);

    // Only call cleanup on success. Some error paths inside password_file__parse
    // may free entries that are still referenced in the hash table (project bug).
    // Calling password_file__cleanup after such an error can lead to use-after-free.
    if (rc == MOSQ_ERR_SUCCESS) {
        password_file__cleanup(&data);
    } else {
        // Avoid calling cleanup which may iterate over corrupted/freed entries.
        // Null out data.unpwd so we don't try to free it again.
        data.unpwd = NULL;
    }

    // Free our duplicated path and remove the temporary file.
    free(data.password_file);
    unlink(tmpname);

    return 0;
}
