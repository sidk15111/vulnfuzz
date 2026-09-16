# OSS-Fuzz-style build container. Base image ships clang + libFuzzer +
# the OSS-Fuzz build helper scripts (compile, compile_afl, etc.).
FROM gcr.io/oss-fuzz-base/base-builder

# This project is self-contained (no upstream repo to clone) - just copy
# the source tree straight into $SRC.
COPY src/ $SRC/vulnfuzz/src/
COPY fuzz/ $SRC/vulnfuzz/fuzz/
COPY seeds/ $SRC/vulnfuzz/seeds/
COPY build.sh $SRC/

WORKDIR $SRC/vulnfuzz
