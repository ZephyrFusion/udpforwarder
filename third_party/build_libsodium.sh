#!/bin/sh
# 下载 libsodium 源码，并用 musl-gcc 编译成静态库
#
# 产物：third_party/libsodium-musl/{include,lib}（已加入 .gitignore）
# 中间产物：third_party/libsodium-<ver>.tar.gz、third_party/libsodium-<ver>/
set -e
cd "$(dirname "$0")"

VER=1.0.20
SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
TARBALL=libsodium-$VER.tar.gz
SRC=libsodium-$VER
PREFIX=$(pwd)/libsodium-musl
URL="https://download.libsodium.org/libsodium/releases/$TARBALL"

if [ -f "$PREFIX/lib/libsodium.a" ]; then
    echo "libsodium.a 已存在，跳过"
    exit 0
fi

if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "找不到 musl-gcc，请先安装 musl-tools" >&2
    exit 1
fi

if [ ! -f "$SRC/configure" ]; then
    # 校验通过就直接用，否则重新下载
    if ! echo "$SHA256  $TARBALL" | sha256sum -c --status 2>/dev/null; then
        echo "下载 $URL"
        rm -f "$TARBALL.part"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --retry 3 -o "$TARBALL.part" "$URL"
        else
            wget -O "$TARBALL.part" "$URL"
        fi
        if ! echo "$SHA256  $TARBALL.part" | sha256sum -c --status; then
            rm -f "$TARBALL.part"
            echo "校验失败：$TARBALL 的 sha256 不匹配" >&2
            exit 1
        fi
        mv "$TARBALL.part" "$TARBALL"
    fi
    echo "解包 $TARBALL"
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
echo "libsodium 静态库已安装到 $PREFIX"
