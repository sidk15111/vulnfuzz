#include <string.h>
#include "vulnlib.h"

/* LEVEL 5 - stack overflow gated behind an exact magic-value compare.
 * CWE-121, reached only past a CWE-1288-style "trust the magic" check.
 *
 * The vulnerable copy only executes if the first 4 payload bytes equal
 * the literal string "FUZZ" (0x46 0x55 0x5A 0x5A). A random byte-flipping
 * mutator has roughly a 1-in-4-billion chance of landing on an exact
 * 4-byte match per attempt, so this level is designed to need whatever
 * comparison-aware help the fuzzing setup provides - AFL++'s CmpLog,
 * laf-intel splitting of the memcmp, a supplied .dict entry for "FUZZ",
 * libFuzzer's value-profile tracing, etc. - rather than raw coverage-
 * guided mutation alone. This is the level most worth watching to judge
 * whether those features are actually wired up and working.
 */
void level5_magic_gate(const uint8_t *data, size_t size) {
    if (size < 8) {
        return;
    }

    if (memcmp(data, "FUZZ", 4) == 0) {
        char buf[8];
        volatile char *vbuf = buf;
        size_t remaining = size - 4;
        size_t copy_len = remaining < 64 ? remaining : 64;

        for (size_t i = 0; i < copy_len; i++) {
            vbuf[i] = data[4 + i]; /* stack overflow once the gate is passed */
        }
    }
}