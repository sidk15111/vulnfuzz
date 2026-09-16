#include <stdint.h>
#include <stddef.h>
#include "../src/vulnlib.h"

/* Standard libFuzzer entry point. AFL++'s aflpp_driver (and OSS-Fuzz's
 * $LIB_FUZZING_ENGINE for libFuzzer) both call this directly, so the
 * same harness works unmodified for both engines. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    process_input(data, size);
    return 0;
}
