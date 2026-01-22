#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h> // tmpfile, getpid, etc.
#include <sys/types.h>

// Ensure the mosquitto_passwd.c compiles without defining main in this TU.
#define WITH_FUZZING 1

// Provide a wrapper so we can include a C source file that uses
// implicit conversion from void* to char* (valid in C but invalid in C++).
// We create malloc_impl before redefining malloc, then redefine malloc to
// cast the result. Undefine the macro after the include so we don't affect
// the rest of the C++ translation unit.
extern "C" {

// helper that calls the real malloc; define it before we override malloc
static inline void *malloc_impl(size_t s) { return ::malloc(s); }

// Temporarily redefine malloc used inside the included C source so
// malloc(...) will be replaced with ((char*)malloc_impl(...))
// which gives the same pointer type expected by the C code.
#define malloc(x) ((char*)malloc_impl(x))

// Include get_password.c so get_password() and get_password__reset_term() are available.
#include "../../apps/mosquitto_passwd/get_password.c"

// Include the project's mosquitto_passwd.c so we get the real pwfile_iterate
// The relative path is from this harness location:
// src/mosquitto/fuzzing/broker/broker_fuzz_queue_msg.cpp
// to the source: src/mosquitto/apps/mosquitto_passwd/mosquitto_passwd.c
#include "../../apps/mosquitto_passwd/mosquitto_passwd.c"

// Done including; remove the malloc macro to avoid affecting other code.
#undef malloc

} // extern "C"

// Provide a fuzz callback compatible with the project's pwfile_iterate callback type.
// Use C linkage to match the included C functions expectation.
extern "C" int fuzz_cb(FILE *fptr, FILE *ftmp, const char *username, const char *password, const char *line, struct cb_helper *helper)
{
    (void)fptr;
    if(line && ftmp){
        fwrite(line, 1, strlen(line), ftmp);
    }
    if(helper && username){
        if(strcmp(username, "FOUND") == 0){
            helper->found = true;
        }
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr) return 0;
    if(Size == 0) return 0;

    // Create a temporary input file and write the fuzzer data into it.
    FILE *fptr = tmpfile();
    if(!fptr) return 0;
    if(Size > 0){
        if(fwrite(Data, 1, Size, fptr) != Size){
            fclose(fptr);
            return 0;
        }
        fflush(fptr);
        rewind(fptr);
    }

    // Create a temporary output file used by callbacks.
    FILE *ftmp = tmpfile();
    if(!ftmp){
        fclose(fptr);
        return 0;
    }

    // Prepare helper struct as expected by the project's pwfile_iterate.
    struct cb_helper helper;
    memset(&helper, 0, sizeof(helper));
    helper.found = false;
    helper.iterations = -1;
    helper.line = nullptr;
    helper.username = nullptr;
    helper.password = nullptr;

    // Call the project's pwfile_iterate (from the included mosquitto_passwd.c).
    // pwfile_iterate is static in the original source, but because we included that
    // source file here, we can call it directly.
    (void)pwfile_iterate(fptr, ftmp, fuzz_cb, &helper);

    // Clean up files
    fclose(fptr);
    fclose(ftmp);

    return 0;
}