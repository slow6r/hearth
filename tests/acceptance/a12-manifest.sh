#!/usr/bin/env bash
# A12 — sha256 бинарей совпадает с манифестом (ТЗ §6.1, §7.3, §12).
set -uo pipefail

MANIFEST="${MANIFEST:-/etc/hearth/manifest.toml}"
[[ -f "$MANIFEST" ]] || { echo "нет $MANIFEST — пропуск"; exit 77; }

status=0

# Плейсхолдеры из поставки — не «почти готово», а незавершённая установка.
if grep -q '0000000000000000000000000000000000000000000000000000000000000000' "$MANIFEST"; then
    echo "  !! в манифесте остались нулевые плейсхолдеры sha256."
    echo "     Узел не может доказать, что запущено. Заполните:"
    echo "       hearthctl manifest pin --name smp-server --version <tag>"
    status=1
fi
if grep -q 'REPLACE-WITH-PINNED-TAG' "$MANIFEST"; then
    echo "  !! в манифесте не проставлены теги upstream (ТЗ §6.1: latest запрещён)"
    status=1
fi

if command -v hearthctl >/dev/null; then
    echo "  hearthctl manifest verify:"
    if hearthctl manifest verify 2>&1 | sed 's/^/    /'; then
        echo "  ok все бинари совпадают с манифестом"
    else
        echo "  !! расхождение — см. вывод выше. hearthd остановит релеи (fail-closed)"
        status=1
    fi
else
    # Резервный путь без hearthctl: считаем хеши по путям из манифеста.
    echo "  hearthctl недоступен, считаю хеши напрямую:"
    paths=$(grep -E '^path' "$MANIFEST" | sed -E 's/^path[[:space:]]*=[[:space:]]*"(.*)"/\1/')
    hashes=$(grep -E '^sha256' "$MANIFEST" | sed -E 's/^sha256[[:space:]]*=[[:space:]]*"(.*)"/\1/')
    paste <(echo "$paths") <(echo "$hashes") | while IFS=$'\t' read -r path expected; do
        [[ -f "$path" ]] || { echo "    !! нет файла $path"; continue; }
        actual="$(sha256sum "$path" | cut -d' ' -f1)"
        if [[ "$actual" == "$expected" ]]; then
            echo "    ok $path"
        else
            echo "    !! $path: ожидалось $expected, получено $actual"
        fi
    done
fi

echo
echo "  Проверка реакции на подмену — только на тестовом стенде:"
echo "    docs/acceptance-tests.md, раздел A12"
exit $status
