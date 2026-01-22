#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "persist.h"
/* Include the property free function declaration so we can free chunk.properties.
   Use the project header path to ensure the prototype is available. */
#include "/src/mosquitto/include/mosquitto/libcommon_properties.h"
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    /* Create a temporary file and write the input bytes into it. */
    FILE *f = tmpfile();
    if(!f) return 0;

    /* Write input to file */
    if(Size > 0){
        if(fwrite(Data, 1, Size, f) != Size){
            fclose(f);
            return 0;
        }
    }
    rewind(f);

    /* Prepare chunk structure (zeroed) */
    struct P_base_msg chunk;
    memset(&chunk, 0, sizeof(chunk));

    /* Call the target function. Cast Size to uint32_t for the length parameter. */
    (void)persist__chunk_base_msg_read_v56(f, &chunk, (uint32_t)Size);

    /* Cleanup: free any heap allocations made into the chunk to avoid leaks between runs. */
    if(chunk.payload){
        free(chunk.payload);
        chunk.payload = NULL;
    }
    if(chunk.topic){
        free(chunk.topic);
        chunk.topic = NULL;
    }
    if(chunk.source.id){
        free(chunk.source.id);
        chunk.source.id = NULL;
    }
    if(chunk.source.username){
        free(chunk.source.username);
        chunk.source.username = NULL;
    }

    /* Free property list allocated by property__read_all / property parsing. */
    mosquitto_property_free_all(&chunk.properties);

    fclose(f);
    return 0;
}
