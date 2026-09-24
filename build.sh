#!/usr/bin/env sh
# Build slide_dev for ASUS Zenfone 9 (SM8475), GKI 5.10.205.
# Requires Android NDK r27+ clang: aarch64-linux-android31-clang (on PATH or via CC=).
set -e

CC="${CC:-aarch64-linux-android31-clang}"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "error: $CC not found. Set CC=/path/to/aarch64-linux-android31-clang" >&2
  exit 1
fi

"$CC" -static -O2 -DZF9_DEVICE -Isrc -pthread \
  src/main.c src/util.c src/slide.c src/fops.c src/pipe.c src/persist.c \
  src/prop.c src/cfi.c src/qmain.c src/seqoverlay.c \
  -o slide_dev

echo "built ./slide_dev ($(wc -c < slide_dev) bytes)"
