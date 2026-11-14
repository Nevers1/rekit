#!/bin/sh
# Build the binaries the emulator is verified against.
#
# Only the sources are in the repository: the outputs are architecture
# specific and are ignored by git. Run this when you want to re-check that
# `rekit emulate` still gets the right numbers, then compare with README.md
# in this directory.
set -e
cd "$(dirname "$0")"

gcc -shared -fPIC -O0 -o libbasic.so basic.c -lm
gcc -shared -fPIC -O0 -o libfuzz.so fuzz.c
gcc -shared -fPIC -O0 -o libjni.so jni.c
gcc -shared -fPIC -O0 -o libhooklib.so hooklib.c
gcc -O0 -o hookhost host.c -L. -lhooklib -Wl,-rpath,'$ORIGIN'

if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    aarch64-linux-gnu-gcc -shared -fPIC -O0 -fno-stack-protector \
        -o libbasic-arm64.so basic.c -lm
    aarch64-linux-gnu-gcc -shared -fPIC -O0 -fno-stack-protector \
        -o libjni-arm64.so jni.c
else
    echo "skipping arm64: aarch64-linux-gnu-gcc not installed" >&2
fi

if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    i686-w64-mingw32-gcc -shared -O0 -o win32.dll win.c -lkernel32
else
    echo "skipping win32: i686-w64-mingw32-gcc not installed" >&2
fi

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc -shared -O0 -o win64.dll win.c -lkernel32
else
    echo "skipping win64: x86_64-w64-mingw32-gcc not installed" >&2
fi

echo "built:"
ls -1 *.so *.dll hookhost 2>/dev/null
