#include <string.h>
#include "vulnlib.h"

/* LEVEL 1 - trivial stack buffer overflow. CWE-121.
 *
 * `buf` is 16 bytes but any payload up to 256 bytes gets memcpy'd into
 * it. There are no preconditions: opcode 0x01 plus any input longer than
 * 16 bytes overflows the buffer. This should be the first crash any
 * working fuzzer setup finds, usually within seconds.
 */
void level1_stack_overflow(const uint8_t *data, size_t size) {
    char buf[16];
    size_t copy_len = size < 256 ? size : 256;

    if (copy_len == 0) {
        return;
    }

    memcpy(buf, data, copy_len); /* overflow when copy_len > sizeof(buf) */

    /* Touch buf so the copy isn't optimized away as dead code. */
    if (buf[0] == 0x00) {
        volatile char sink = buf[0];
        (void)sink;
    }
}
