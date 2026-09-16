#!/bin/bash -eu
#
# Builds the vulnfuzz fuzz target the way OSS-Fuzz expects: compile
# object files with $CC/$CFLAGS, then link the fuzz target with $CXX
# (required even for pure-C projects) against $LIB_FUZZING_ENGINE.

cd "$SRC/vulnfuzz"

$CC $CFLAGS -c src/parser.c                    -o "$WORK/parser.o"
$CC $CFLAGS -c src/level1_stack_overflow.c      -o "$WORK/level1.o"
$CC $CFLAGS -c src/level2_heap_offbyone.c       -o "$WORK/level2.o"
$CC $CFLAGS -c src/level3_int_overflow.c        -o "$WORK/level3.o"
$CC $CFLAGS -c src/level4_use_after_free.c      -o "$WORK/level4.o"
$CC $CFLAGS -c src/level5_magic_gate.c          -o "$WORK/level5.o"
$CC $CFLAGS -c fuzz/fuzz_process.c              -o "$WORK/fuzz_process.o"

$CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
  "$WORK/parser.o" "$WORK/level1.o" "$WORK/level2.o" "$WORK/level3.o" \
  "$WORK/level4.o" "$WORK/level5.o" "$WORK/fuzz_process.o" \
  -o "$OUT/fuzz_process"

# Seed corpus: one starting file per opcode so the fuzzer's mutations
# begin from a valid dispatch byte instead of having to discover each
# opcode value from nothing. Delete this step (or the seeds/ directory)
# if you'd rather benchmark cold-start discovery of the opcodes too.
#if [ -d seeds ]; then
#  zip -j "$OUT/fuzz_process_seed_corpus.zip" seeds/*
#fi
