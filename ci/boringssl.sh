#!/bin/sh
# boringssl.sh OUT_DIR builds the pinned BoringSSL into OUT_DIR/lib/libcrypto.a and OUT_DIR/include,
# then prints the CGO_CFLAGS and CGO_LDFLAGS of a cgo build of pkg/vpc/relay/dp/aead.
# The pin is the release 0.20261020.0, which is also the BCR module boringssl 0.20261020.0.
set -eu
version=0.20261020.0 # Commit d3bf4795ad5b79d646cddf2fec687da5b9b502db.
sha256=fb43aac7fbd323c9dfa1f45fe92a1c01142433c05b23fe34f61d6ba8b13b642e
[ $# -eq 1 ] || { echo "usage: $0 OUT_DIR" >&2; exit 2; }
mkdir -p "$1"
out=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/src.tar.gz" "https://github.com/google/boringssl/releases/download/$version/boringssl-$version.tar.gz"
if command -v sha256sum >/dev/null; then
	got=$(sha256sum "$work/src.tar.gz" | cut -d' ' -f1)
else
	got=$(shasum -a 256 "$work/src.tar.gz" | cut -d' ' -f1)
fi
[ "$got" = "$sha256" ] || { echo "the BoringSSL tarball has sha256 $got, not $sha256" >&2; exit 1; }
tar -xzf "$work/src.tar.gz" -C "$work"
# Release with -O2 and with no asserts.
cmake -S "$work/boringssl-$version" -B "$work/build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-O2 -DNDEBUG" -DBUILD_TESTING=OFF >&2
ninja -C "$work/build" crypto >&2
mkdir -p "$out/lib"
cp "$work/build/libcrypto.a" "$out/lib/libcrypto.a"
rm -rf "$out/include"
cp -R "$work/boringssl-$version/include" "$out/include"
case $(uname -s) in
Darwin) cxx=-lc++ ;;
*) cxx=-lstdc++ ;;
esac
# A set CGO_CFLAGS replaces the default of Go (-O2 -g) for all cgo packages, so keep it.
echo "CGO_CFLAGS=-O2 -g -I$out/include"
echo "CGO_LDFLAGS=$out/lib/libcrypto.a $cxx -lpthread"
