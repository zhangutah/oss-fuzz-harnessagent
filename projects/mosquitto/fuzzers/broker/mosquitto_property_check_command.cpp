#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
#include "/src/mosquitto/include/mosquitto.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) return 0;

    // Helper to read up to 4 bytes from Data starting at offset, little-endian,
    // padding with zeros if not enough bytes available.
    auto read_u32_le = [&](size_t offset)->uint32_t {
        uint32_t v = 0;
        for(size_t i = 0; i < 4; ++i){
            size_t idx = offset + i;
            uint8_t b = 0;
            if(idx < Size) b = Data[idx];
            v |= (uint32_t)b << (8 * i);
        }
        return v;
    };

    uint32_t command_u32 = read_u32_le(0);
    uint32_t identifier_u32 = read_u32_le(4);

    int command = static_cast<int>(command_u32);
    int identifier = static_cast<int>(identifier_u32);

    // Call the target function. We ignore the return value.
    (void)mosquitto_property_check_command(command, identifier);

    return 0;
}
