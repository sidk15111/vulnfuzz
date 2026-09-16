#include "vulnlib.h"

/* data[0] selects which vulnerable path handles the rest of the input.
 * This mirrors how a real parser dispatches on a type/opcode field, and
 * gives every path an equal, cheap-to-reach entry point so that the
 * *difficulty ladder* comes entirely from what happens after dispatch,
 * not from finding the opcode itself. */
void process_input(const uint8_t *data, size_t size) {
    if (size < 1) {
        return;
    }

    uint8_t opcode = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    switch (opcode) {
        case 0x01:
            level1_stack_overflow(payload, payload_size);
            break;
        case 0x02:
            level2_heap_offbyone(payload, payload_size);
            break;
        case 0x03:
            level3_int_overflow(payload, payload_size);
            break;
        case 0x04:
            level4_use_after_free(payload, payload_size);
            break;
        case 0x05:
            level5_magic_gate(payload, payload_size);
            break;
        default:
            /* Unknown opcode: no-op. Keeps exploration of this branch
             * cheap instead of penalizing the fuzzer for guessing wrong. */
            break;
    }
}
