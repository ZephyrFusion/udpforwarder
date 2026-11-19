#!/bin/sh
# Downloads the libsodium source tarball and builds a static library with musl-gcc.
#
# Output:  third_party/libsodium-musl/{include,lib} (git-ignored)
# Byproducts: third_party/libsodium-<ver>.tar.gz, third_party/libsodium-<ver>/
set -e
cd "$(dirname "$0")"

VER=1.0.20
SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
TARBALL=libsodium-$VER.tar.gz
SRC=libsodium-$VER
PREFIX=$(pwd)/libsodium-musl
URL="https://download.libsodium.org/libsodium/releases/$TARBALL"

if [ -f "$PREFIX/lib/libsodium.a" ]; then
    echo "libsodium.a already present, skipping"
    exit 0
fi

if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "musl-gcc not found, please install musl-tools" >&2
    exit 1
fi

if [ ! -f "$SRC/configure" ]; then
    # reuse the tarball if its checksum matches, otherwise download it again
    if ! echo "$SHA256  $TARBALL" | sha256sum -c --status 2>/dev/null; then
        echo "downloading $URL"
        rm -f "$TARBALL.part"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --retry 3 -o "$TARBALL.part" "$URL"
        else
            wget -O "$TARBALL.part" "$URL"
        fi
        if ! echo "$SHA256  $TARBALL.part" | sha256sum -c --status; then
            rm -f "$TARBALL.part"
            echo "checksum mismatch for $TARBALL" >&2
            exit 1
        fi
        mv "$TARBALL.part" "$TARBALL"
    fi
    echo "extracting $TARBALL"
    rm -rf "$SRC"
    tar xzf "$TARBALL"
fi

cd "$SRC"
make distclean >/dev/null 2>&1 || true
CC=musl-gcc CFLAGS="-O2 -fPIC" ./configure \
    --prefix="$PREFIX" \
    --host=x86_64-linux-musl \
    --disable-shared \
    --enable-static \
    --disable-asm \
    --without-pthreads \
    >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
echo "static libsodium installed into $PREFIX"
