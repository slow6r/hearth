#!/usr/bin/env bash
# Разложить overlay/ по форку (ТЗ §8.1).
#
# Overlay — это файлы, которые форк ДОБАВЛЯЕТ: они не живут в чужих файлах и потому
# не конфликтуют при ребейзе. Но лежат они в этом репозитории, а собирается форк,
# поэтому перед сборкой их надо разложить по местам. Раньше это делалось руками —
# и ровно так теряются файлы: тот, кто клонирует репозиторий, получает overlay,
# кладёт его никуда и собирает сборку без половины правок.
#
# Скрипт идемпотентный: гоняйте перед каждой сборкой.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVERLAY="$HERE/overlay"
FORK="${FORK_DIR:-$HERE/simplex-chat}/apps/multiplatform"

[ -d "$FORK" ] || { echo "нет форка: $FORK — см. android/README.md" >&2; exit 1; }

copied=0
copy() {
    local src="$1" dst="$2"
    mkdir -p "$(dirname "$dst")"
    # Сравниваем перед копированием: так вывод показывает, что реально разъехалось,
    # а mtime не дёргается зря — gradle пересобирает по нему.
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then return 0; fi
    cp "$src" "$dst"
    echo "  → ${dst#"$FORK"/}"
    copied=$((copied + 1))
}

echo "== overlay → форк"
while IFS= read -r rel; do
    case "$rel" in
        # Не файл сборки, а образец для описания патча 0005: манифест upstream
        # правится точечно, целиком его подменять нельзя.
        android/src/main/AndroidManifest-hearth.xml) continue ;;
        # Adaptive-иконка нужна под двумя именами. Держать в overlay два одинаковых
        # файла — значит однажды поправить один и забыть второй.
        android/src/main/res/mipmap-anydpi-v26-icon.xml)
            copy "$OVERLAY/$rel" "$FORK/android/src/main/res/mipmap-anydpi-v26/icon.xml"
            copy "$OVERLAY/$rel" "$FORK/android/src/main/res/mipmap-anydpi-v26/icon_round.xml"
            continue ;;
    esac
    copy "$OVERLAY/$rel" "$FORK/$rel"
done < <(cd "$OVERLAY" && find . -type f | sed 's|^\./||' | sort)

if [ "$copied" -eq 0 ]; then
    echo "  всё уже на месте"
else
    echo "== обновлено файлов: $copied"
fi
