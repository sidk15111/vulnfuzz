#include <stdlib.h>
#include "vulnlib.h"

/* LEVEL 4 - use-after-free via a tiny stateful "VM". CWE-416.
 *
 * The whole ordered sequence of sub-operations lives inside one input
 * buffer (the standard OSS-Fuzz pattern for "needs a specific sequence"
 * bugs, since a fuzz target only sees one buffer per run):
 *
 *   0xA1  ALLOC  - allocate a new 64-byte block (frees any prior one)
 *   0xA2  FREE   - free the current block, but forget to clear the
 *                  pointer (the actual bug)
 *   0xA3  <byte> WRITE - write <byte> through the pointer
 *
 * A crash needs FREE (0xA2) to occur, with no intervening ALLOC, before
 * a WRITE (0xA3). Each sub-opcode is its own branch, so a coverage-
 * guided fuzzer gets an incremental signal for discovering ALLOC, then
 * FREE, then WRITE, then finally the FREE-before-WRITE *ordering* - but
 * still needs to land on three specific rare byte values in the right
 * relative order, which plain random mutation finds much more slowly
 * than levels 1-3.
 */
void level4_use_after_free(const uint8_t *data, size_t size) {
    char *ptr = NULL;
    int allocated = 0; /* bookkeeping only, for the end-of-function cleanup -
                         * WRITE below never consults this, only `ptr` itself,
                         * which is what makes the dangling-pointer bug real */
    size_t i = 0;

    while (i < size) {
        uint8_t op = data[i++];

        switch (op) {
            case 0xA1: /* ALLOC */
                if (allocated) {
                    free(ptr);
                }
                ptr = (char *)malloc(64);
                allocated = 1;
                break;

            case 0xA2: /* FREE */
                if (allocated) {
                    free(ptr);
                    allocated = 0;
                    /* bug: ptr itself is not reset to NULL here, so it
                     * keeps pointing at freed memory */
                }
                break;

            case 0xA3: /* WRITE <byte> */
                if (ptr != NULL && i < size) {
                    ptr[0] = data[i]; /* use-after-free once FREE has run without a following ALLOC */
                    i++;
                }
                break;

            default:
                break;
        }
    }

    if (allocated) {
        free(ptr); /* avoid leak-detector noise on inputs that only ever ALLOC */
    }
}
