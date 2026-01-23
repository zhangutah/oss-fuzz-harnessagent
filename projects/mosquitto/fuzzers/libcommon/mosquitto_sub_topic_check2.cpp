#include <cstddef>
#include <cstdint>
#include <algorithm>

#ifndef libmosqcommon_EXPORT
#define libmosqcommon_EXPORT
#endif

#include "/src/mosquitto/include/mosquitto/libcommon_topic.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Data == nullptr || Size == 0) return 0;

    const size_t MAX_TOPIC_LEN = 65535;
    size_t topiclen = (Size > MAX_TOPIC_LEN) ? MAX_TOPIC_LEN : Size;

    const char *topic = reinterpret_cast<const char *>(Data);

    (void)mosquitto_sub_topic_check2(topic, topiclen);
    if (topiclen > 1) {
        (void)mosquitto_sub_topic_check2(topic, topiclen - 1);
    }

    return 0;
}