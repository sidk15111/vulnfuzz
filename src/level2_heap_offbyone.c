#include <stdlib.h>
#include "vulnlib.h"

/* LEVEL 2 - off-by-one heap buffer overflow. CWE-193 / CWE-787.
 *
 * Allocates exactly `size` bytes but the copy loop runs from i = 0
 * through i = size inclusive, writing one byte past the end of the heap
 * allocation. Unlike level 1 this needs a non-empty payload, but any
 * non-empty payload triggers it deterministically - no specific value
 * is required, so it should still be found quickly, just a step behind
 * level 1.
 */
void level2_heap_offbyone(const uint8_t *data, size_t size) {
    if (size == 0) {
        return;
    }

    char *buf = (char *)malloc(size);
    if (!buf) {
        return;
    }

    volatile char *vbuf = buf; /* every write through vbuf is a real,
                                 * observable access - the compiler can't
                                 * prove it's dead regardless of what
                                 * happens afterward */
    for (size_t i = 0; i <= size; i++) { /* bug: should be i < size */
        vbuf[i] = data[i < size ? i : 0];
    }

    free(buf);
}