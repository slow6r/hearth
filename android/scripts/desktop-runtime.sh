#!/usr/bin/env bash
# Разложить нативные библиотеки Windows по местам перед сборкой десктопа.
#
# Гоняется ПЕРЕД :desktop:createDistributable / :desktop:packageMsi.
#
# Почему скриптом, а не руками: gradle-задача cmakeBuildAndCopy пересобирает
# build/links/windows-x64 из каталога сборки cmake, где лежит только libapp-lib.dll.
# Всё остальное — ядро и VLC — она затирает, и установщик молча выходит без них.
# Приложение при этом ставится и падает при запуске на UnsatisfiedLinkError.
#
# Откуда берутся сами файлы — android/README.md, раздел «Десктоп (Windows)»:
# из официального релиза upstream, с проверкой хеша из двух сетей.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$HERE/desktop-runtime/windows-x64"
FORK="${FORK_DIR:-$HERE/simplex-chat}/apps/multiplatform"
LINKS="$FORK/build/links/windows-x64"
CPPLIBS="$FORK/common/src/commonMain/cpp/desktop/libs/windows-x86_64"

[ -d "$SRC" ] || {
    echo "нет $SRC — библиотеки не распакованы, см. android/README.md" >&2
    exit 1
}
for f in libsimplex.dll libcrypto-3-x64.dll vlc/libvlc.dll vlc/libvlccore.dll; do
    [ -e "$SRC/$f" ] || { echo "нет $SRC/$f" >&2; exit 1; }
done

# Ядро нужно ещё и на этапе линковки libapp-lib.dll — там оно берётся из cpp/libs.
mkdir -p "$CPPLIBS" "$LINKS"
cp -f "$SRC/libsimplex.dll" "$CPPLIBS/libsimplex.dll"
cp -rf "$SRC/." "$LINKS/"

echo "== разложено в $LINKS"
ls "$LINKS" | sed 's/^/  /'
echo "  плагинов vlc: $(ls "$LINKS/vlc/plugins" 2>/dev/null | wc -l)"
