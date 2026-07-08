#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-third_party/checkers}"
VERSION="v05.22.2023"
REVISION="2e5e29cb0019d5cfd547d4208dca1b3ec290349f"
REPOSITORY="https://github.com/marijnheule/drat-trim.git"
SOURCE="$PREFIX/src/drat-trim-$REVISION"
BINARY="$PREFIX/bin/drat-trim"

mkdir -p "$PREFIX/src" "$PREFIX/bin"
if [ ! -d "$SOURCE/.git" ]; then
  git clone --filter=blob:none --no-checkout "$REPOSITORY" "$SOURCE"
fi
git -C "$SOURCE" fetch --depth 1 origin "$REVISION"
git -C "$SOURCE" checkout --detach "$REVISION"
make -C "$SOURCE" drat-trim
install -m 0755 "$SOURCE/drat-trim" "$BINARY"

printf 'drat_trim_version=%s\n' "$VERSION"
printf 'drat_trim_revision=%s\n' "$(git -C "$SOURCE" rev-parse HEAD)"
printf 'drat_trim_binary=%s\n' "$BINARY"
