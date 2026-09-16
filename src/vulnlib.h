#ifndef VULNLIB_H
#define VULNLIB_H

#include <stddef.h>
#include <stdint.h>

/* Single entry point used by the fuzz harness. Dispatches on the first
 * byte of the input to one of five intentionally-vulnerable code paths.
 * The paths are ordered by how hard they should be for a coverage-guided
 * fuzzer to reach and trigger - see README.md for the difficulty
 * rationale of each one. */
void process_input(const uint8_t *data, size_t size);

void level1_stack_overflow(const uint8_t *data, size_t size);
void level2_heap_offbyone(const uint8_t *data, size_t size);
void level3_int_overflow(const uint8_t *data, size_t size);
void level4_use_after_free(const uint8_t *data, size_t size);
void level5_magic_gate(const uint8_t *data, size_t size);

#endif /* VULNLIB_H */
