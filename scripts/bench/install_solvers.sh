#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEST="${1:-$ROOT/third_party/solvers}"
UNAME_S="$(uname -s)"
UNAME_M="$(uname -m)"
BUILD_Z3_API_RUNNER=0
YICES_REQUIRED=0

mkdir -p "$DEST/downloads" "$DEST/bin"

download_checked() {
  local url="$1"
  local sha="$2"
  local out="$3"
  if [ ! -f "$out" ]; then
    curl -L --fail --retry 3 --output "$out" "$url"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    echo "$sha  $out" | sha256sum -c -
  else
    local actual
    actual="$(shasum -a 256 "$out" | awk '{print $1}')"
    if [ "$actual" != "$sha" ]; then
      echo "sha256 mismatch for $out" >&2
      exit 1
    fi
  fi
}

install_zip_binary() {
  local zip="$1"
  local name="$2"
  local pattern="$3"
  local tmp="$DEST/.extract-$name"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  unzip -q "$zip" -d "$tmp"
  local bin
  bin="$(find "$tmp" -type f -path "$pattern" -perm -111 | head -1)"
  if [ -z "$bin" ]; then
    bin="$(find "$tmp" -type f -name "$name" | head -1)"
  fi
  if [ -z "$bin" ]; then
    echo "could not find $name in $zip" >&2
    exit 1
  fi
  cp "$bin" "$DEST/bin/$name"
  chmod +x "$DEST/bin/$name"
}

install_tar_binary() {
  local archive="$1"
  local name="$2"
  local pattern="$3"
  local tmp="$DEST/.extract-$name"
  rm -rf "$tmp"
  mkdir -p "$tmp"
  tar -xzf "$archive" -C "$tmp"
  local bin
  bin="$(find "$tmp" -type f -path "$pattern" -perm -111 | head -1)"
  if [ -z "$bin" ]; then
    bin="$(find "$tmp" -type f -name "$name" | head -1)"
  fi
  if [ -z "$bin" ]; then
    echo "could not find $name in $archive" >&2
    exit 1
  fi
  cp "$bin" "$DEST/bin/$name"
  chmod +x "$DEST/bin/$name"
}

case "$UNAME_S:$UNAME_M" in
  Linux:x86_64)
    CVC5_URL="https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.4/cvc5-Linux-x86_64-static.zip"
    CVC5_SHA="dcdbfada0ce493ee98259c0816e0daafc561c223aadb3af298c2968e73ea39c6"
    YICES_URL="https://github.com/SRI-CSL/yices2/releases/download/yices-2.7.0/yices-2.7.0-x86_64-pc-linux-gnu-static-gmp.tar.gz"
    YICES_SHA="49566b6f817692820538df78fe406878400d79810631c9372b2495bc81d3e00a"
    YICES_REQUIRED=1
    GLIBC_VERSION="$(ldd --version 2>/dev/null | head -1 | sed -E 's/.* ([0-9]+)\.([0-9]+).*/\1 \2/' || true)"
    GLIBC_MAJOR="$(printf '%s\n' "$GLIBC_VERSION" | awk '{print $1}')"
    GLIBC_MINOR="$(printf '%s\n' "$GLIBC_VERSION" | awk '{print $2}')"
    if [ "${GLIBC_MAJOR:-0}" -gt 2 ] || { [ "${GLIBC_MAJOR:-0}" -eq 2 ] && [ "${GLIBC_MINOR:-0}" -ge 39 ]; }; then
      Z3_URL="https://github.com/Z3Prover/z3/releases/download/z3-4.16.0/z3-4.16.0-x64-glibc-2.39.zip"
      Z3_SHA="7288c49a5bd6dbafd7b0b0d1f65956b91672da24b08f09242919af159be3418e"
    else
      Z3_URL=""
      Z3_SHA=""
      BUILD_Z3_API_RUNNER=1
    fi
    ;;
  Darwin:arm64)
    CVC5_URL="https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.4/cvc5-macOS-arm64-static.zip"
    CVC5_SHA="3840aa53f6ee6fc357415dcfe291d7f5ffec6cfb1ccca6fef64120a0d2be4cb6"
    YICES_URL="https://github.com/SRI-CSL/yices2/releases/download/yices-2.7.0/yices-2.7.0-arm-apple-darwin24.5.0-static-gmp.tar.gz"
    YICES_SHA="5682fedf13add7818e8d05796b9133e67844fce2bb72fd1ecc75dcb73167c7ac"
    Z3_URL=""
    Z3_SHA=""
    ;;
  Darwin:x86_64)
    CVC5_URL="https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.4/cvc5-macOS-x86_64-static.zip"
    CVC5_SHA="5a7976affaf37dcf03ee44c3d0297c8e0ba08afd44ac832dab97400da726b852"
    YICES_URL="https://github.com/SRI-CSL/yices2/releases/download/yices-2.7.0/yices-2.7.0-x86_64-apple-darwin21.6.0-static-gmp.tar.gz"
    YICES_SHA="dff40838ae5674abed2c08c383d702c1358ad64627c15799d2a15e67d1b4495a"
    Z3_URL="https://github.com/Z3Prover/z3/releases/download/z3-4.16.0/z3-4.16.0-x64-osx-15.7.3.zip"
    Z3_SHA="d95519c4f3ed9393bb5f996e514c8f177bb148989bdfc32e95587f0307c4e7b0"
    ;;
  *)
    echo "unsupported platform $UNAME_S $UNAME_M" >&2
    exit 1
    ;;
esac

CVC5_ZIP="$DEST/downloads/$(basename "$CVC5_URL")"
download_checked "$CVC5_URL" "$CVC5_SHA" "$CVC5_ZIP"
install_zip_binary "$CVC5_ZIP" cvc5 '*/bin/cvc5'

YICES_TAR="$DEST/downloads/$(basename "$YICES_URL")"
download_checked "$YICES_URL" "$YICES_SHA" "$YICES_TAR"
install_tar_binary "$YICES_TAR" yices-smt2 '*/bin/yices-smt2'

if [ -n "$Z3_URL" ]; then
  Z3_ZIP="$DEST/downloads/$(basename "$Z3_URL")"
  download_checked "$Z3_URL" "$Z3_SHA" "$Z3_ZIP"
  install_zip_binary "$Z3_ZIP" z3 '*/bin/z3'
elif [ "$BUILD_Z3_API_RUNNER" = 1 ]; then
  python3 - <<'PY' >/dev/null 2>&1 || python3 -m pip install --user z3-solver==4.16.0.0
import z3
assert z3.get_version_string() == "4.16.0"
PY
  Z3_PACKAGE_DIR="$(python3 -c 'import pathlib, z3; print(pathlib.Path(z3.__file__).parent)')"
  "${CC:-cc}" -O2 -DNDEBUG \
    -I "$Z3_PACKAGE_DIR/include" \
    "$ROOT/scripts/bench/z3_native_runner.c" \
    -L "$Z3_PACKAGE_DIR/lib" \
    -Wl,-rpath,"$Z3_PACKAGE_DIR/lib" \
    -lz3 \
    -o "$DEST/bin/z3"
elif command -v z3 >/dev/null 2>&1; then
  ln -sf "$(command -v z3)" "$DEST/bin/z3"
else
  echo "z3 release asset not configured for $UNAME_S $UNAME_M and no z3 on PATH" >&2
fi

"$DEST/bin/cvc5" --version | head -1
if YICES_VERSION="$("$DEST/bin/yices-smt2" --version 2>&1)"; then
  printf '%s\n' "$YICES_VERSION" | head -1
elif [ "$YICES_REQUIRED" = 1 ]; then
  printf '%s\n' "$YICES_VERSION" >&2
  exit 1
else
  printf 'warning: official Yices binary is unavailable on this host: %s\n' \
    "$YICES_VERSION" >&2
  rm -f "$DEST/bin/yices-smt2"
fi
if [ -x "$DEST/bin/z3" ]; then
  "$DEST/bin/z3" -version
fi
