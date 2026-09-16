#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vulnlib.h"

/* LEVEL 3 - integer overflow leading to an undersized allocation.
 * CWE-190 -> CWE-787.
 *
 * Reads a 4-byte little-endian "requested" size, then reserves a 16-byte
 * header in front of it: alloc_size = requested + 16, computed as a
 * 32-bit unsigned add. Only when `requested` is within 16 of UINT32_MAX
 * does that addition wrap around to a tiny value while the code still
 * copies the fuzzer's actual (unrelated, much larger) payload length
 * into the buffer.
 *
 * That's a narrow ~16-value-wide target out of the 2^32 possible
 * "requested" values, so plain random mutation is unlikely to land on
 * it quickly. It's deliberately still within reach of AFL/AFL++'s
 * "interesting values" deterministic stage (which tries boundary
 * constants like 0xFFFFFFFF), so it's meant to sit above levels 1-2
 * without requiring comparison-solving assistance.
 */
void level3_int_overflow(const uint8_t *data, size_t size) {
    if (size < 4) {
        return;
    }

    uint32_t requested = (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
                          ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);

    const uint8_t *payload = data + 4;
    size_t payload_size = size - 4;

    uint32_t alloc_size = requested + 16;

    char *buf = (char *)malloc(alloc_size);
    if (!buf) {
        return;
    }

    volatile char *vbuf = buf;
    for (size_t i = 0; i < payload_size; i++) {
        vbuf[16 + i] = payload[i]; /* heap overflow once alloc_size wrapped small */
    }

    free(buf);
}