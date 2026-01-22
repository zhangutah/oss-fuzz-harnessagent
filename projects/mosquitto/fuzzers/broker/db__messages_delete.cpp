#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

/* The mosquitto project headers are C headers. When compiling this harness as C++,
 * we must include them with C linkage to avoid C++ name mangling for functions
 * implemented in C (e.g., db__messages_delete).
 */
extern "C" {
#include "/src/mosquitto/src/mosquitto_broker_internal.h"
#include "/src/mosquitto/lib/mosquitto_internal.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if(!Data || Size == 0) {
        return 0;
    }

    /* Create a minimal, zero-initialized mosquitto context. This avoids
     * relying on other project initialization functions and keeps lists NULL
     * so db__messages_delete won't attempt to free complex structures.
     */
    struct mosquitto *context = (struct mosquitto *)malloc(sizeof(struct mosquitto));
    if(!context) return 0;
    memset(context, 0, sizeof(struct mosquitto));

    /* Determine force_free from first byte */
    bool force_free = (Data[0] & 0x1) ? true : false;

    /* Use subsequent bytes (if present) to toggle fields that influence
     * the behavior of db__messages_delete.
     * - Data[1] bit0: whether to allocate and attach a bridge
     * - Data[2] bit0: context->clean_start
     * - Data[3] bit0: bridge->clean_start
     * - Data[4] bit0: bridge->clean_start_local (treated as int8_t)
     */
    if(Size > 2) {
        context->clean_start = (Data[2] & 0x1) ? true : false;
    } else {
        context->clean_start = false;
    }

    struct mosquitto__bridge *bridge = NULL;
    if(Size > 1 && (Data[1] & 0x1)) {
        bridge = (struct mosquitto__bridge *)malloc(sizeof(struct mosquitto__bridge));
        if(bridge) {
            memset(bridge, 0, sizeof(struct mosquitto__bridge));
            if(Size > 3) {
                bridge->clean_start = (Data[3] & 0x1) ? true : false;
            } else {
                bridge->clean_start = false;
            }
            if(Size > 4) {
                bridge->clean_start_local = (int8_t)(Data[4] & 0x1);
            } else {
                bridge->clean_start_local = 0;
            }
            /* attach to context */
            context->bridge = bridge;
        } else {
            context->bridge = NULL;
        }
    } else {
        context->bridge = NULL;
    }

    /* Ensure msg lists are NULL (they are already because of memset),
     * but be explicit to avoid any surprises.
     */
    context->msgs_in.inflight = NULL;
    context->msgs_in.queued = NULL;
    context->msgs_out.inflight = NULL;
    context->msgs_out.queued = NULL;

    /* Call the target function under test. */
    (void)db__messages_delete(context, force_free);

    /* Clean up allocated bridge (if any) and context. The code under test
     * should not have stored pointers to these allocations after return,
     * because we provided empty lists and minimal state.
     */
    if(bridge) {
        free(bridge);
    }
    free(context);

    return 0;
}
