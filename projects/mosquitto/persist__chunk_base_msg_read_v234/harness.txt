#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "/src/mosquitto/src/persist.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(Data == nullptr) return 0;

    /* Create a temporary file, write the fuzz input to it and rewind.
     * Using a temporary file is portable across platforms. */
    FILE *f = tmpfile();
    if(!f) return 0;

    if(Size > 0){
        if(fwrite(Data, 1, Size, f) != Size){
            fclose(f);
            return 0;
        }
    }
    rewind(f);

    /* Prepare an empty P_base_msg and ensure pointers are NULL so the
     * called function's error cleanup behaves predictably. */
    struct P_base_msg chunk;
    memset(&chunk, 0, sizeof(chunk));

    /* Choose a db_version based on input to exercise both code paths.
     * If the first input byte is odd, use v4 (which reads username & port),
     * otherwise use v3-like behaviour. */
    uint32_t db_version = 3;
    if(Size > 0 && (Data[0] & 1)) db_version = 4;

    int rc = persist__chunk_base_msg_read_v234(f, &chunk, db_version);

    /* On success the function returns MOSQ_ERR_SUCCESS and leaves allocated
     * pointers for us to free; on error it goes to error: and frees them
     * itself, so only free on success to avoid double-free. */
    if(rc == MOSQ_ERR_SUCCESS){
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
        if(chunk.properties){
            /* properties is a pointer type; persist code doesn't set it here,
             * but free defensively if non-NULL. */
            free(chunk.properties);
            chunk.properties = NULL;
        }
    }

    fclose(f);
    return 0;
}
