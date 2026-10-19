#!/bin/sh
here="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
sys="$(uname -s)"
case "$sys" in
MINGW* | MSYS* | CYGWIN*) rel="x86_64-pc-windows-msvc/gray-latchkey.exe" ;;
Darwin*)
    case "$(uname -m)" in
    arm64) rel="aarch64-apple-darwin/gray-latchkey" ;;
    *) rel="x86_64-apple-darwin/gray-latchkey" ;;
    esac ;;
*)
    case "$(uname -m)" in
    aarch64 | arm64) rel="aarch64-unknown-linux-musl/gray-latchkey" ;;
    *) rel="x86_64-unknown-linux-musl/gray-latchkey" ;;
    esac ;;
esac
if [ -x "$here/$rel" ]; then exec "$here/$rel" "$@"; fi
for cand in "$here/target/release/gray-latchkey.exe" "$here/target/release/gray-latchkey" "$here/target/debug/gray-latchkey.exe" "$here/target/debug/gray-latchkey"; do
    if [ -x "$cand" ]; then exec "$cand" "$@"; fi
done
echo "gray-latchkey binary not found in $here" >&2
exit 1
