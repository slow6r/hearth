#!/usr/bin/env bash
# Прогон Kotlin-тестов форка.
#
#   android/scripts/run-tests.sh
#
# ЗАЧЕМ ОТДЕЛЬНЫЙ СКРИПТ. Тесты в репозитории были, а команды, которая их запускает,
# не было ни в одном из скриптов: build-release.sh их не гоняет. То есть сторож,
# написанный «чтобы следующий ребейз не сломал правило», сам никем не проверялся —
# ровно так защита превращается в украшение. Проверять надо тем, что лежит в
# репозитории, а не тем, что кто-то однажды набрал руками.
#
# Задача :common:desktopTest собирает commonMain и commonTest под JVM, поэтому она
# заодно служит быстрой проверкой компиляции — минуты полторы против полной сборки APK.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/simplex-chat}/apps/multiplatform"

[ -d "$FORK" ] || { echo "нет форка: $FORK — см. android/README.md" >&2; exit 1; }

# Overlay раскладываем перед прогоном: тесты лежат в overlay, и без раскладки
# проверялась бы прошлая копия в форке, а не то, что сейчас в репозитории.
bash "$HERE/scripts/sync-overlay.sh"

cd "$FORK"
./gradlew :common:desktopTest --no-daemon

echo
echo "== итоги по классам"
found=0
while IFS= read -r f; do
    found=1
    grep -o 'name="[^"]*" tests="[0-9]*" skipped="[0-9]*" failures="[0-9]*" errors="[0-9]*"' "$f" \
        | head -1 | sed 's/name="//; s/"//g; s/^/  /'
done < <(find common/build/test-results -name 'TEST-*.xml' 2>/dev/null | sort)

# Пустой вывод не должен выглядеть как успех: если XML не нашлись, значит задача
# отработала вхолостую, и «ничего не упало» тут ничего не значит.
if [ "$found" -eq 0 ]; then
    echo "  !! результатов тестов нет — прогон не состоялся" >&2
    exit 1
fi
