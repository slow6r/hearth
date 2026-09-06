#!/usr/bin/env bash
# Сверка реального ini релея с эталоном намерений hearth.
#
# ТЗ §6.2 прямо говорит: «имена ключей уточнить по версии». Этот скрипт показывает
# расхождения, но НИЧЕГО НЕ ПРАВИТ — решение, как перенести намерение на новые имена
# ключей, принимает человек.
#
#   ./verify-ini-keys.sh /etc/opt/simplex/smp-server.ini smp/smp-server.ini.example
#
# Вывод:
#   MISSING  — ключ из эталона отсутствует (или в этой версии называется иначе)
#   DIFFERS  — ключ есть, значение другое
#   EXTRA    — ключ есть только в реальном файле (обычно это нормально)
set -euo pipefail

ACTUAL="${1:?usage: verify-ini-keys.sh <actual.ini> <expected.ini.example>}"
EXPECTED="${2:?usage: verify-ini-keys.sh <actual.ini> <expected.ini.example>}"

norm() {
    # "key: value" / "key = value" -> "key<TAB>value"; без комментариев и пустых строк
    sed -e 's/#.*$//' -e 's/[[:space:]]*$//' "$1" \
        | grep -E '^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*[[:space:]]*[:=]' \
        | sed -E 's/^[[:space:]]*([A-Za-z0-9_]+)[[:space:]]*[:=][[:space:]]*(.*)$/\1\t\2/'
}

ACTUAL_KEYS="$(mktemp)"
EXPECTED_KEYS="$(mktemp)"
trap 'rm -f "$ACTUAL_KEYS" "$EXPECTED_KEYS"' EXIT
norm "$ACTUAL"   | sort > "$ACTUAL_KEYS"
norm "$EXPECTED" | sort > "$EXPECTED_KEYS"

status=0
while IFS="$(printf '\t')" read -r key value; do
    [ -z "$key" ] && continue
    actual_value="$(awk -F'\t' -v k="$key" '$1==k {print $2; exit}' "$ACTUAL_KEYS")"
    if [ -z "$actual_value" ]; then
        echo "MISSING  $key   (эталон: $value)"
        status=1
    elif [ "$value" != "$actual_value" ] && ! printf '%s' "$value" | grep -q '^REPLACE_WITH_'; then
        echo "DIFFERS  $key   эталон: $value   реально: $actual_value"
        status=1
    fi
done < "$EXPECTED_KEYS"

while IFS="$(printf '\t')" read -r key _; do
    [ -z "$key" ] && continue
    if ! awk -F'\t' -v k="$key" '$1==k {found=1} END {exit !found}' "$EXPECTED_KEYS"; then
        echo "EXTRA    $key"
    fi
done < "$ACTUAL_KEYS"

echo
if [ $status -eq 0 ]; then
    echo "Все ключи эталона присутствуют и совпадают."
else
    echo "Есть расхождения. Требования ТЗ §6.2/§6.3 — таблица в relays/README.md §3."
fi
exit $status
