#!/usr/bin/env bash
# Выгрузить наши коммиты форка в репозиторий: серией патчей и бандлом.
#
# Форк — отдельный git-репозиторий и в основной не входит (android/FORK.md).
# Чтобы связь «APK ↔ исходники» жила в git, а не в переписке, наши коммиты поверх
# upstream-тега лежат здесь в двух видах: патчи читаются глазами и дают построчный
# дифф, бандл сохраняет авторство и даты.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/simplex-chat}"
BASE="${1:-v7.0.1}"
OUT="$HERE/fork-patches"

git -C "$FORK" rev-parse "$BASE" >/dev/null 2>&1 || {
    echo "нет базового тега $BASE в $FORK" >&2
    exit 1
}
DIRTY="$(git -C "$FORK" status --porcelain)"
[ -z "$DIRTY" ] || {
    echo "дерево форка изменено — сначала закоммитьте:" >&2
    printf '%s\n' "$DIRTY" >&2
    exit 1
}

rm -rf "$OUT"
mkdir -p "$OUT"
git -C "$FORK" format-patch "$BASE..HEAD" -o "$OUT" --no-signature >/dev/null
git -C "$FORK" bundle create "$OUT/hearth-mobile-fork.bundle" "$BASE..HEAD"

HEAD_SHA="$(git -C "$FORK" rev-parse HEAD)"
BASE_SHA="$(git -C "$FORK" rev-parse "$BASE")"
echo "патчей: $(find "$OUT" -name '*.patch' | wc -l)"
echo "коммит форка: $HEAD_SHA"
echo "база: $BASE ($BASE_SHA)"
echo
echo "Обновите android/FORK.md, если коммит сборки изменился."
