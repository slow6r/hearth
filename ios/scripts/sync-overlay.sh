#!/usr/bin/env bash
# Разложить ios/overlay по форку и зарегистрировать файлы в проекте Xcode.
#
# То же назначение, что у android/scripts/sync-overlay.sh, и одно отличие: проект iOS
# в классическом формате, файл без записи в project.pbxproj в сборку не попадает.
# Поэтому здесь два шага, и второй важнее первого.
#
# Идемпотентный: гоняйте перед каждой сборкой.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OVERLAY="$HERE/overlay"
FORK="${FORK_DIR:-$HERE/../android/simplex-chat}/apps/ios"
PBX="$FORK/SimpleX.xcodeproj/project.pbxproj"

[ -f "$PBX" ] || { echo "нет форка: $FORK — см. ios/README.md" >&2; exit 1; }

copied=0
copy() {
    local src="$1" dst="$2"
    mkdir -p "$(dirname "$dst")"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then return 0; fi
    cp "$src" "$dst"
    echo "  → ${dst#"$FORK"/}"
    copied=$((copied + 1))
}

echo "== overlay → форк"
while IFS= read -r rel; do
    copy "$OVERLAY/$rel" "$FORK/$rel"
done < <(cd "$OVERLAY" && find SimpleXChat Shared -type f -name '*.swift' 2>/dev/null | sort)
[ "$copied" -eq 0 ] && echo "  всё уже на месте"

# Package.swift и Tests/ в форк не едут: пакет существует только затем, чтобы
# `swift test` гонял логику без ядра и без проекта Xcode.

# `|| true`: каталога ресурсов до bake-node.sh нет, и под pipefail пустой find иначе
# молча оборвал бы весь скрипт — именно на шаге, который сообщает, чего не хватает.
list() { (cd "$FORK" && find "$1" -maxdepth 1 -type f -name "$2" 2>/dev/null | sort) || true; }

echo "== файлы → project.pbxproj"
# shellcheck disable=SC2046
python3 "$HERE/scripts/pbx-add.py" "$PBX" SimpleXChat sources SimpleXChat/Hearth $(list SimpleXChat/Hearth '*.swift')
# shellcheck disable=SC2046
python3 "$HERE/scripts/pbx-add.py" "$PBX" "SimpleX (iOS)" sources Shared/Hearth $(list Shared/Hearth '*.swift')

# Вшитые ресурсы узла кладёт bake-node.sh. Регистрируем, только если они есть: сборка
# без них соберётся, но на экране кода скажет «сборка неполная» — так и задумано.
RES="$(list SimpleXChat/Hearth/Resources '*')"
if [ -n "$RES" ]; then
    # shellcheck disable=SC2086
    python3 "$HERE/scripts/pbx-add.py" "$PBX" SimpleXChat resources SimpleXChat/Hearth/Resources $RES
else
    echo "  ресурсов узла нет — сначала ios/scripts/bake-node.sh"
fi

plutil -lint "$PBX" >/dev/null && echo "== project.pbxproj разбирается"
