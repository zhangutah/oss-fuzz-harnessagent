// Fixed harness: write fuzz data to the temporary file using low-level write(2)
// (loop until all bytes written), ensure an fsync before close, and then call
// mosquitto_read_file. Using write() avoids partial writes that sometimes occur
// with stdio in edge cases and guarantees the fuzz input is actually present
// on disk when mosquitto_read_file opens the file.
//
// File: /src/mosquitto/fuzzing/broker/broker_fuzz_queue_msg.cpp

#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

// Some project headers declare symbols like "libmosqcommon_EXPORT ...".
// If that macro is not defined the compiler sees it as an unknown type.
// Define it (empty) so the header declarations compile correctly.
#ifndef libmosqcommon_EXPORT
#define libmosqcommon_EXPORT
#endif

// Include the header that declares mosquitto_read_file using the absolute path
// as in the original harness.
extern "C" {
#include "/src/mosquitto/include/mosquitto/libcommon_file.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Data == nullptr || Size == 0) {
        return 0;
    }

    // Create a secure temporary file.
    char tmpl[] = "/tmp/mosq_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Ensure file permissions are restrictive (owner read/write).
    // mkstemp normally creates 0600, but set explicitly to be sure.
    fchmod(fd, S_IRUSR | S_IWUSR);

    // Write all input bytes to the file using write(2) in a loop to handle
    // partial writes robustly.
    const uint8_t *ptr = Data;
    size_t remaining = Size;
    while (remaining > 0) {
        ssize_t w = write(fd, ptr, remaining);
        if (w <= 0) {
            // write error; cleanup and exit.
            close(fd);
            unlink(tmpl);
            return 0;
        }
        ptr += w;
        remaining -= (size_t)w;
    }

    // Ensure data is flushed to disk before other readers open it.
    fsync(fd);
    close(fd);

    // Decide restrict_read flag from first byte.
    bool restrict_read = (Data[0] & 1) != 0;

    char *buf = nullptr;
    size_t buflen = 0;

    // Call the function under test. The file contains the full fuzz input,
    // so the function will see data-dependent contents.
    int rc = mosquitto_read_file(tmpl, restrict_read, &buf, &buflen);

    // If a buffer was allocated by mosquitto_read_file, use it to ensure
    // the fuzz data influences program execution (trim blanks and compute checksum).
    if (buf) {
        // mosquitto_read_file allocates buflen+1 bytes (zeroed by calloc),
        // so buf is NUL-terminated and safe to treat as a string for trimming.
        char *trimmed = mosquitto_trimblanks(buf);
        (void)trimmed;

        // Compute a simple checksum over the returned buffer contents.
        // Use volatile so the compiler won't optimize the loop away.
        volatile uint8_t checksum = 0;
        for (size_t i = 0; i < buflen; i++) {
            checksum ^= (uint8_t)buf[i];
        }
        // Use the checksum in a branch so it affects observable control flow.
        if (checksum == 0xFF) {
            // No-op; the branch purpose is to make coverage sensitive to data.
            (void)checksum;
        }

        free(buf);
        buf = nullptr;
    }

    // Remove the temporary file.
    unlink(tmpl);

    (void)rc;
    return 0;
}
