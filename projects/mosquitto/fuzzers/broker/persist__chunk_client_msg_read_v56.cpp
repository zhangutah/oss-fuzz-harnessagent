#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <climits>
#include <cerrno>
#include <arpa/inet.h> /* for ntohs if needed */

/*
 * Include the C header with C linkage so declarations match our C-linkage
 * definitions below.
 */
extern "C" {
#include "/src/mosquitto/src/persist.h" /* persist__chunk_client_msg_read_v56, struct P_client_msg */
}

/*
 * Minimal stubs to satisfy link-time dependencies in the fuzz build.
 *
 * The real persist__chunk_client_msg_read_v56 lives in the project's source tree
 * (persist_read_v5.c). Do NOT provide a fake implementation here 2 use the real one
 * by including persist.h and linking the project object files.
 *
 * Keep simple stubs for fuzz_packet_read_init / fuzz_packet_read_cleanup in case
 * other objects reference them and they are not present in the linked objects.
 */

extern "C" {

/* Stub for fuzz_packet_read_init referenced by some other objects. Return 0 on success. */
int fuzz_packet_read_init(struct mosquitto * /*context*/)
{
    return 0;
}

/* Stub for fuzz_packet_read_cleanup referenced by some other objects. */
void fuzz_packet_read_cleanup(struct mosquitto * /*context*/)
{
    /* no-op */
}

} /* extern "C" */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data) return 0;

    /* Create a temporary file and write the fuzz data into it. */
    FILE *f = tmpfile();
    if(!f) return 0;

    if(Size > 0){
        size_t written = fwrite(Data, 1, Size, f);
        if(written != Size){
            /* If we couldn't write all data, clean up and exit. */
            fclose(f);
            return 0;
        }
        rewind(f);
    }

    /* Prepare the chunk structure expected by the function. */
    struct P_client_msg chunk;
    memset(&chunk, 0, sizeof(chunk));
    chunk.clientid = NULL;
    chunk.subscription_identifier = 0;

    /* Clamp the size to uint32_t range for the function parameter. */
    uint32_t length = (Size > UINT32_MAX) ? UINT32_MAX : (uint32_t)Size;

    /* Call the real target function from the project. */
    (void)persist__chunk_client_msg_read_v56(f, &chunk, length);

    /* Clean up memory possibly allocated by the function.
     * The project usually uses mosquitto_malloc/mosquitto_FREE for allocation/free;
     * free() is used here as a fallback to avoid leaks in the harness. */
    if(chunk.clientid){
        free(chunk.clientid);
        chunk.clientid = NULL;
    }

    fclose(f);
    return 0;
}
