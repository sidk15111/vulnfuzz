# vulnfuzz

A deliberately-vulnerable, multi-file C project for exercising a
ClusterFuzz + AFL++ pipeline end-to-end. It has one fuzz entry point
(`process_input`) that dispatches on an opcode byte to five independent
bugs of increasing difficulty, so you can watch how long your setup
takes to find each one and get a rough read on where its limits are.

Verified locally with `gcc -fsanitize=address,undefined`: each level
crashes with the expected sanitizer report on a crafted input and stays
silent on a neighboring non-crashing input (see "Local sanity check"
below) - the bugs are real, not just eyeballed.

## Layout

```
vulnfuzz/
├── src/
│   ├── vulnlib.h                  - shared declarations
│   ├── parser.c                   - opcode dispatcher (process_input)
│   ├── level1_stack_overflow.c    - CWE-121, trivial
│   ├── level2_heap_offbyone.c     - CWE-193/787, easy
│   ├── level3_int_overflow.c      - CWE-190->787, medium
│   ├── level4_use_after_free.c    - CWE-416, medium-hard
│   └── level5_magic_gate.c        - CWE-121 behind CWE-1288, hard
├── fuzz/
│   └── fuzz_process.c             - LLVMFuzzerTestOneInput harness
├── seeds/                         - one benign seed file per opcode
├── test_harness/
│   └── standalone_main.c          - reads a file, calls process_input once
│                                     (not part of the OSS-Fuzz build; only
│                                     for quick local repro with plain gcc)
├── Dockerfile
├── build.sh
└── project.yaml
```

## Input format

`data[0]` is an opcode selecting the bug; everything after it is that
bug's payload:

| Opcode | Handler                  | Difficulty  |
|--------|---------------------------|-------------|
| `0x01` | `level1_stack_overflow`   | Trivial     |
| `0x02` | `level2_heap_offbyone`    | Easy        |
| `0x03` | `level3_int_overflow`     | Medium      |
| `0x04` | `level4_use_after_free`   | Medium-hard |
| `0x05` | `level5_magic_gate`       | Hard        |

Any other opcode is a no-op, so wrong guesses are cheap for the fuzzer
rather than penalized.

## The difficulty ladder

1. **Stack overflow (trivial).** `memcpy`s up to 256 bytes into a
   16-byte buffer. No precondition at all - opcode `0x01` plus any
   input over 16 bytes crashes it. This is the "is anything working"
   smoke test; it should fall in seconds.

2. **Heap off-by-one (easy).** Allocates exactly `size` bytes, then a
   loop writes `size + 1`. Any non-empty payload triggers it
   deterministically, but it needs one more precondition (non-empty)
   than level 1, so it's a small step up.

3. **Integer overflow -> undersized allocation (medium).** Adds a
   16-byte header size to a 32-bit "requested" length; only when
   `requested` is within 16 of `UINT32_MAX` does that addition wrap to
   a tiny allocation while the code still copies the fuzzer's full
   payload into it. That's a narrow ~16-value band out of 2^32, so
   plain random mutation is unlikely to land on it quickly - but
   AFL/AFL++'s deterministic "interesting values" stage tries boundary
   constants like `0xFFFFFFFF`, so it should still be reachable without
   comparison-solving help, just slower than levels 1-2.

4. **Use-after-free via a tiny stateful VM (medium-hard).** The payload
   is itself a sequence of sub-opcodes: `0xA1` allocates, `0xA2` frees
   (without nulling the pointer - the actual bug), `0xA3 <byte>` writes
   through the pointer. A crash needs `0xA2` to run, with no
   intervening `0xA1`, before `0xA3`. Each sub-opcode is its own
   branch, so coverage guidance helps the fuzzer discover them one at a
   time, but it still has to land on three specific rare byte values in
   the right relative order - noticeably harder than levels 1-3 for a
   fuzzer with no structure-aware/grammar mutator.

5. **Magic-gated overflow (hard).** The vulnerable copy only runs if
   the first 4 payload bytes exactly equal `"FUZZ"`. A byte-flipping
   mutator has about a 1-in-4-billion chance per attempt of an exact
   4-byte match, so this level is meant to need whatever
   comparison-aware assistance your setup provides - AFL++ CmpLog,
   laf-intel splitting of the `memcmp`, a `.dict` entry, etc. It's the
   one most worth watching to confirm those features are actually
   wired up: if it falls in minutes, your comparison-solving is working;
   if it never falls, that's useful information about the setup, not
   about the bug.

No seed corpus entry or dictionary contains the `"FUZZ"` magic value on
purpose - handing that to the fuzzer would just tell it the answer to
level 5 instead of testing whether it can find it.

## Local sanity check (already done for you, but to repeat it)

```bash
gcc -g -O0 -fsanitize=address,undefined -Isrc \
  src/parser.c src/level1_stack_overflow.c src/level2_heap_offbyone.c \
  src/level3_int_overflow.c src/level4_use_after_free.c src/level5_magic_gate.c \
  test_harness/standalone_main.c -o vulnfuzz_test

# level 1
printf '\x01AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' > /tmp/l1 && ./vulnfuzz_test /tmp/l1   # stack-buffer-overflow
# level 5 (needs the exact magic + >=4 more bytes)
python3 -c "open('/tmp/l5','wb').write(b'\x05FUZZ' + b'D'*40)" && ./vulnfuzz_test /tmp/l5  # stack-buffer-overflow
```

---

## Build path A - validate against real OSS-Fuzz tooling

Since your pipeline is copying OSS-Fuzz's project layout, the fastest
way to confirm this project is *structurally* correct is to run it
through OSS-Fuzz's own `infra/helper.py`, independent of your
self-hosted setup:

```bash
git clone --depth 1 https://github.com/google/oss-fuzz.git
cp -r vulnfuzz oss-fuzz/projects/vulnfuzz
cd oss-fuzz

python3 infra/helper.py build_image vulnfuzz
python3 infra/helper.py build_fuzzers --sanitizer address vulnfuzz
python3 infra/helper.py check_build vulnfuzz
python3 infra/helper.py run_fuzzer --corpus-dir=/tmp/corpus vulnfuzz fuzz_process
```

`build_fuzzers` drops the compiled target in
`oss-fuzz/build/out/vulnfuzz/fuzz_process`; `check_build` confirms it
runs and actually crashes on a bad input; `run_fuzzer` starts libFuzzer
against it so you can watch level 1 fall almost immediately. You can
repeat `build_fuzzers` with `--sanitizer undefined` and
`--engine afl` too, since `project.yaml` lists both `libfuzzer` and
`afl` as supported engines.

This step never touches your self-hosted ClusterFuzz - it's purely to
confirm the project.yaml/Dockerfile/build.sh contract is satisfied
before you adapt the build for your own pipeline below.

## Build path B - your self-hosted CUSTOM_BINARY/AFL++ pipeline

Per your setup, `CUSTOM_BINARY` targets have to be compiled inside a
container matching the bot environment (Ubuntu 20.04, clang/LLVM 14),
instrumented with your source-built AFL++, and linked against
`aflpp_driver` - not built with a host-machine compiler. Reuse the same
bot image you already pushed to your project's container registry:

```bash
docker run --rm -it \
  -v "$(pwd)/vulnfuzz:/src/vulnfuzz" \
  -w /src/vulnfuzz \
  <your-registry>/<your-ubuntu20-bot-image>:<tag> \
  bash
```

Then, inside that container (adjust paths to wherever you installed
your AFL++ build and `LLVM_CONFIG=llvm-config-14`):

```bash
export CC=/path/to/afl-clang-fast
export CXX=/path/to/afl-clang-fast++
export CFLAGS="-g -O1 -fsanitize=address"
export CXXFLAGS="$CFLAGS"

$CC $CFLAGS -c src/parser.c                -o parser.o
$CC $CFLAGS -c src/level1_stack_overflow.c  -o level1.o
$CC $CFLAGS -c src/level2_heap_offbyone.c   -o level2.o
$CC $CFLAGS -c src/level3_int_overflow.c    -o level3.o
$CC $CFLAGS -c src/level4_use_after_free.c  -o level4.o
$CC $CFLAGS -c src/level5_magic_gate.c      -o level5.o
$CC $CFLAGS -c fuzz/fuzz_process.c          -o fuzz_process.o

# Statically link against the aflpp_driver object you already built
# from AFL++'s utils/aflpp_driver against this same LLVM_CONFIG.
$CXX $CXXFLAGS \
  parser.o level1.o level2.o level3.o level4.o level5.o fuzz_process.o \
  /path/to/aflpp_driver.o \
  -o fuzz_process
```

The result is a single self-contained `fuzz_process` binary that reads
one input file per invocation (or loops in AFL++ persistent mode, if
`aflpp_driver` was built with `AFL_PERSISTENT` support) - the same
contract your existing CUSTOM_BINARY jobs already expect. Package and
upload it exactly the way your working "basic pipeline" job does today
(same archive layout, same GCS path/job template), then point a
`CUSTOM_BINARY` job at it, optionally seeding it with the files in
`seeds/`.

### What to watch for

Once it's running, level 1 falling almost immediately is your
end-to-end smoke test - bot picks up the job, executes the binary,
detects the crash, reports it back. Levels 2-4 falling within a
reasonable window tell you coverage-guided mutation is doing its job.
Level 5's fate is the most informative data point: if it doesn't fall
within a time budget you'd consider reasonable, that's a concrete
signal to check whether CmpLog/laf-intel is actually enabled in your
AFL++ build rather than just present in the source tree.
