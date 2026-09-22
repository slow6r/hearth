#!/usr/bin/env bash
# Собрать Haskell-ядро iOS из исходников форка и разложить в apps/ios/Libraries.
#
#   ios/scripts/build-core.sh device   # arm64 для телефона — только Mac на Apple Silicon
#   ios/scripts/build-core.sh sim      # симулятор: на Intel — x86_64, на Apple Silicon — arm64
#
# Готовых iOS-библиотек upstream не публикует, а из приложения в App Store их не
# извлечь (docs/adr/0015). Собираем тем же flake.nix, что и upstream CI; скрипт
# повторяет scripts/ios/prepare*.sh, только берёт результат из nix, а не из ~/Downloads.
#
# Не проверено на живой сборке: первый прогон на чистой машине — часы.
set -euo pipefail

TARGET="${1:?usage: build-core.sh device|sim}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/../android/simplex-chat}"
LIBS="$FORK/apps/ios/Libraries"
HOST="$(uname -m)"

command -v nix >/dev/null || { echo "нужен nix с включёнными flakes" >&2; exit 1; }

DIRTY="$(git -C "$FORK" status --porcelain -- src cabal.project flake.nix flake.lock simplex-chat.cabal)"
if [ -n "$DIRTY" ] && [ "${HEARTH_ALLOW_DIRTY:-0}" != "1" ]; then
    echo "исходники ядра в форке изменены — ядро было бы не сопоставить с коммитом:" >&2
    printf '%s\n' "$DIRTY" >&2
    exit 1
fi

case "$TARGET:$HOST" in
    device:arm64) SYSTEM=aarch64-darwin; ATTR="aarch64-darwin-ios:lib:simplex-chat"; DEST=ios; FLAG="" ;;
    device:*)     echo "ядро для телефона собирается только на Apple Silicon (flake.nix upstream)" >&2; exit 1 ;;
    sim:arm64)    SYSTEM=aarch64-darwin; ATTR="aarch64-darwin-ios:lib:simplex-chat"; DEST=sim; FLAG="-s" ;;
    sim:x86_64)   SYSTEM=x86_64-darwin;  ATTR="x86_64-darwin-ios:lib:simplex-chat";  DEST=sim; FLAG="-s" ;;
    *)            echo "неизвестная цель $TARGET на $HOST" >&2; exit 1 ;;
esac

echo "== nix build $SYSTEM.$ATTR"
OUT="$(nix build --no-link --print-out-paths "$FORK#packages.$SYSTEM.\"$ATTR\"")"
ZIP="$(find "$OUT" -maxdepth 1 -name 'pkg-ios-*-swift-json.zip' | head -1)"
[ -n "$ZIP" ] || { echo "в $OUT нет pkg-ios-*-swift-json.zip" >&2; exit 1; }

# mac2ios — из того же flake.lock, что и сборка, а не «последний с GitHub».
MAC2IOS="$(nix build --no-link --print-out-paths --inputs-from "$FORK" 'mac2ios#mac2ios')/bin/mac2ios"

rm -rf "${LIBS:?}/$DEST"
mkdir -p "$LIBS/$DEST"
unzip -o -q "$ZIP" -d "$LIBS/$DEST"
chmod +w "$LIBS/$DEST"/*
for f in "$LIBS/$DEST"/*.a; do
    # shellcheck disable=SC2086
    "$MAC2IOS" $FLAG "$f" >/dev/null
done

# Только для device: update-pbxproj.sh читает Libraries/ios и при сборке симулятора
# падает на его отсутствии, обрывая скрипт уже после удачной сборки ядра.
if [ "$DEST" = ios ]; then
    (cd "$FORK" && sh scripts/ios/update-pbxproj.sh)
fi

(cd "$LIBS/$DEST" && shasum -a 256 ./*.a > SHA256SUMS)
echo "== $LIBS/$DEST"
cat "$LIBS/$DEST/SHA256SUMS"
echo "коммит форка: $(git -C "$FORK" rev-parse HEAD)"
