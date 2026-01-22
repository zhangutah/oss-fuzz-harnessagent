#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Mosquitto core headers are C; ensure C linkage when included from C++.
extern "C" {
#include "/src/mosquitto/lib/packet_mosq.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0){
        return 0;
    }

    // Copy input to a mutable buffer because packet__read_* functions read from payload and advance pos.
    uint8_t *buf = (uint8_t *)malloc(Size);
    if(!buf){
        return 0;
    }
    memcpy(buf, Data, Size);

    struct mosquitto__packet_in packet;
    memset(&packet, 0, sizeof(packet));
    packet.payload = buf;
    packet.remaining_length = (uint32_t)Size;
    packet.pos = 0;

    // Call the target function.
    char *str = nullptr;
    uint16_t length = 0;
    (void)packet__read_string(&packet, &str, &length);

    // packet__read_string may allocate memory for str using mosquitto_malloc/mosquitto_FREE.
    // Free any allocated memory to avoid leaks during fuzzing.
    if(str){
        free(str);
        str = nullptr;
    }

    free(buf);
    return 0;
}
