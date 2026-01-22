// broker_fuzz_queue_msg.cpp
// Fuzz driver for: int psk__file_parse(struct mosquitto__psk ** psk_id, const char * psk_file);

#include <cstdint>
#include <cstddef>
#include <cstdbool>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

// Prevent inclusion of the project's libcommon_memory.h so we can provide
// alternate declarations that match how the C source assigns returned pointers.
// The header's include guard is MOSQUITTO_LIBCOMMON_MEMORY_H.
#ifndef MOSQUITTO_LIBCOMMON_MEMORY_H
#define MOSQUITTO_LIBCOMMON_MEMORY_H
#endif

extern "C" {
// Forward declarations of types that will be defined by the project's headers
struct mosquitto;
struct mosquitto__config;
struct mosquitto__psk;
struct mosquitto_db; /* struct mosquitto_db is defined in mosquitto_broker_internal.h */

// Provide minimal declarations (matching how psk_file.c uses them).
// Note: we intentionally declare mosquitto_malloc returning char* and
// mosquitto_calloc returning struct mosquitto__psk* so the included C file
// (compiled as part of this C++ TU) can assign results without C++ void*
// -> typed-pointer implicit conversion errors.

char *mosquitto_malloc(size_t size);
struct mosquitto__psk *mosquitto_calloc(size_t nmemb, size_t size);
void mosquitto_free(void *p);
#define mosquitto_FREE(A) do{ mosquitto_free(A); (A)=NULL; }while(0)
char *mosquitto_strdup(const char *s);
char *mosquitto_trimblanks(char *s);
FILE *mosquitto_fopen(const char *path, const char *mode, bool restrict_read);
char *mosquitto_fgets(char **buf, int *buflen, FILE *stream);
int log__printf(struct mosquitto *mosq, unsigned int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#include "/src/mosquitto/src/psk_file.c"
} // extern "C"

// Provide implementations for the helper functions declared above.
extern "C" {

// Return a char* pointer matching usage in psk_file.c.
char *mosquitto_malloc(size_t size) {
    return (char *)malloc(size);
}

// Return a struct mosquitto__psk* pointer matching usage in psk_file.c.
struct mosquitto__psk *mosquitto_calloc(size_t nmemb, size_t size) {
    return (struct mosquitto__psk *)calloc(nmemb, size);
}

// Provide mosquitto_free implementation.
void mosquitto_free(void *p) {
    free(p);
}

// mosquitto_strdup matches project's prototype.
char *mosquitto_strdup(const char *s) {
    if(!s) return nullptr;
    return strdup(s);
}

// Simple trim blanks implementation (in-place). Returns pointer to string start.
char *mosquitto_trimblanks(char *s) {
    if(!s) return s;
    // Trim leading
    char *start = s;
    while(*start && (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')) start++;
    if(start != s) memmove(s, start, strlen(start) + 1);
    // Trim trailing
    size_t len = strlen(s);
    while(len && (s[len-1] == ' ' || s[len-1] == '\t' || s[len-1] == '\r' || s[len-1] == '\n')) {
        s[len-1] = '\0';
        len--;
    }
    return s;
}

FILE *mosquitto_fopen(const char *path, const char *mode, bool /*restrict_read*/) {
    return fopen(path, mode);
}

// The project's header declares: char *mosquitto_fgets(char **buf, int *buflen, FILE *stream);
// Return the buffer on success, NULL on failure.
char *mosquitto_fgets(char **buf, int *buflen, FILE *f) {
    if(!buf || !*buf || !buflen || *buflen <= 0 || !f) return NULL;
    if(fgets(*buf, *buflen, f) == NULL) return NULL;
    return *buf;
}

// Match the project's logging prototype exactly.
int log__printf(struct mosquitto * /*mosq*/, unsigned int /*level*/, const char * /*fmt*/, ...) {
    // No-op for fuzz harness to keep output quiet.
    return 0;
}

} // extern "C"

// Define the global 'db' variable the project expects. The struct type is defined
// by the included headers inside psk_file.c (through its includes). Declare and
// instantiate it here so the linker has a definition (the header declares it as extern).
extern "C" {
struct mosquitto_db db = { 0 };
}

// Fuzzer entry point must keep this exact signature.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Ensure db.config is non-NULL so psk__file_parse proceeds.
    static struct mosquitto__config cfg;
    db.config = &cfg;

    // Create a temporary file to hold the fuzzer input.
    char tmpname[] = "/tmp/pskfile_fuzz_XXXXXX";
    int fd = mkstemp(tmpname);
    if(fd < 0) return 0;
    // Write input bytes to the file.
    ssize_t wrote = write(fd, Data, (Size > 0) ? Size : 0);
    (void)wrote;
    close(fd);

    // Prepare root pointer for psk entries.
    struct mosquitto__psk *root = NULL;

    // Call the target function with the path to the temp file.
    // psk__file_parse is static in the original file but available here because we included the .c.
    int rc = psk__file_parse(&root, tmpname);
    (void)rc; // we don't assert on return code in the fuzz harness.

    // Clean up allocated PSK entries if any were added.
    psk__cleanup(&root);

    // Remove the temporary file.
    unlink(tmpname);

    return 0;
}
