#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <algorithm>
#include <ctype.h>

// Forward declaration for the struct used by psk_file.c so helper functions can use its pointer type.
extern "C" {
    struct mosquitto__psk;
}

// Provide minimal implementations of mosquitto helper functions so that
// including the C file in this C++ TU compiles correctly (avoid void* -> typed pointer assignments).
// These are intentionally simple wrappers around standard libc functions.

extern "C" {

// Prevent inclusion of the libcommon headers that would declare conflicting prototypes
// (they would declare different return types and produce "functions that differ only in return type"
// compile errors). By defining the include-guard macros here, the headers included by psk_file.c
// will be skipped and our replacements below will be used instead.
#define MOSQUITTO_LIBCOMMON_FILE_H
#define MOSQUITTO_LIBCOMMON_MEMORY_H

// Return type uses char* because psk_file.c assigns this return to a char* (buf).
static inline char *mosquitto_malloc(size_t size)
{
    if(size == 0) return nullptr;
    return (char *)malloc(size);
}

// mosquitto_calloc is used in psk_file.c to allocate a struct mosquitto__psk*.
static inline struct mosquitto__psk *mosquitto_calloc(size_t nmemb, size_t size)
{
    return (struct mosquitto__psk *)calloc(nmemb, size);
}

static inline void mosquitto_free(void *p)
{
    free(p);
}
#define mosquitto_FREE(A) do{ mosquitto_free(A); (A) = NULL;}while(0)

static inline char *mosquitto_strdup(const char *s)
{
    if(!s) return NULL;
    return strdup(s);
}

// simple wrapper for fopen; the third parameter (restrict) is ignored for this harness.
static inline FILE *mosquitto_fopen(const char *path, const char *mode, int /*restrict*/)
{
    return fopen(path, mode);
}

// mosquitto_fgets(&buf, &buflen, stream)
// Return pointer to buffer on success, NULL on EOF/error. Matches the library's prototype (char*).
static inline char *mosquitto_fgets(char **bufp, int *buflenp, FILE *stream)
{
    if(!bufp || !buflenp || !stream) return NULL;

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen = getline(&line, &linecap, stream);
    if(linelen == -1){
        free(line);
        return NULL;
    }

    // Ensure buffer is large enough (buflen is int; convert safely).
    if((int)linecap > *buflenp){
        char *newbuf = (char *)realloc(*bufp, linecap);
        if(!newbuf){
            free(line);
            return NULL;
        }
        *bufp = newbuf;
        *buflenp = (int)linecap;
    }

    // Copy line into provided buffer and null-terminate.
    memcpy(*bufp, line, (size_t)linelen);
    (*bufp)[linelen] = '\0';

    free(line);
    return *bufp;
}

// Trim leading and trailing whitespace (in-place). Returns the pointer to trimmed string.
static inline char *mosquitto_trimblanks(char *s)
{
    if(!s) return s;
    // Trim leading
    char *start = s;
    while(*start && isspace((unsigned char)*start)) start++;
    // Trim trailing
    char *end = start + strlen(start);
    while(end > start && isspace((unsigned char)*(end-1))) end--;
    *end = '\0';
    // If we moved start, shift the string back to s buffer.
    if(start != s) memmove(s, start, strlen(start) + 1);
    return s;
}

// Minimal logging function used by psk_file.c. Print to stderr.
static inline int log__printf(void * /*unused_client*/, int /*level*/, const char *fmt, ...)
{
    if(!fmt) return 0;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    return 0;
}

} // extern "C"

// Now include the C source so we can call the static pwfile__parse function.
// Including the .c here compiles its code into this C++ translation unit; the helper wrappers above
// ensure the C code compiles under C++ (avoiding implicit void* conversions).
extern "C" {
#include "/src/mosquitto/src/psk_file.c"
}

// LLVM fuzzing entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr || Size == 0){
        return 0;
    }

    // Create a temporary file to hold the fuzz input (pwfile content).
    char tmpl[] = "/tmp/pwfile_fuzz_XXXXXX";
    int fd = mkstemp(tmpl);
    if(fd == -1){
        return 0;
    }

    // Write Data to the temporary file.
    const uint8_t *p = Data;
    size_t remaining = Size;
    while(remaining > 0){
        ssize_t w = write(fd, p, remaining);
        if(w <= 0) break;
        p += w;
        remaining -= (size_t)w;
    }

    // Ensure data is flushed and file descriptor closed.
    fsync(fd);
    close(fd);

    // Prepare root pointer for pwfile__parse to populate.
    struct mosquitto__psk *root = NULL;

    // Call the target static function (available because we included the .c).
    // pwfile__parse expects a filename and pointer to root.
    (void)pwfile__parse(tmpl, &root);

    // Cleanup any created structures. psk__cleanup is static in the same .c.
    // It gracefully handles NULL.
    psk__cleanup(&root);

    // Remove temporary file.
    unlink(tmpl);

    return 0;
}
