#!/usr/bin/env bash
# Проверки самих проверок: прогон разбора по фикстурам.
#
# Гейт выпуска, который никто не проверял, — это не гейт. Здесь функции из
# lib/apk-checks.sh гоняются по сохранённым кускам настоящего вывода Android-
# инструментов, включая заведомо плохие: сборку с включённым бэкапом, с отладкой,
# подписанную чужим ключом, с секретом в ресурсе.
#
#   ./run.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/apk-checks.sh
source "$HERE/../lib/apk-checks.sh"

FIXTURES="$HERE/fixtures"
failures=0
checks=0

# expect <ожидание: pass|fail> <описание> <функция> <аргументы...>
expect() {
    local want="$1" what="$2"
    shift 2
    checks=$((checks + 1))
    local out rc
    out="$("$@" 2>&1)"
    rc=$?
    local got="pass"
    [[ $rc -eq 0 ]] || got="fail"
    if [[ "$got" == "$want" ]]; then
        printf '  OK    %s\n' "$what"
    else
        printf '  FAIL  %s (ожидалось %s, получено %s: %s)\n' "$what" "$want" "$got" "$out" >&2
        failures=$((failures + 1))
    fi
}

read_fixture() { cat "$FIXTURES/$1"; }

echo "== allowBackup"
expect pass "выключённый бэкап проходит" check_allow_backup "$(read_fixture manifest-good.txt)"
expect fail "включённый бэкап не проходит" check_allow_backup "$(read_fixture manifest-backup-on.txt)"
expect fail "бэкап в двоичной форме true не проходит" check_allow_backup "$(read_fixture manifest-backup-binary-true.txt)"
expect fail "отсутствующий атрибут не проходит" check_allow_backup "$(read_fixture manifest-backup-missing.txt)"
expect fail "пустой манифест не проходит" check_allow_backup ""

echo "== debuggable"
expect pass "релизная сборка проходит" check_not_debuggable "$(read_fixture manifest-good.txt)"
expect fail "сборка с отладкой не проходит" check_not_debuggable "$(read_fixture manifest-debuggable.txt)"

echo "== прочие атрибуты манифеста"
expect pass "network security config на месте" check_network_security_config "$(read_fixture manifest-good.txt)"
expect fail "без network security config — отказ" check_network_security_config "$(read_fixture manifest-backup-missing.txt)"
expect pass "правила извлечения данных заданы" check_data_extraction_rules "$(read_fixture manifest-good.txt)"
expect pass "testOnly отсутствует" check_not_test_only "$(read_fixture manifest-good.txt)"
expect fail "testOnly ловится" check_not_test_only "$(read_fixture manifest-testonly.txt)"
expect pass "лишних разрешений нет" check_no_extra_permissions "$(read_fixture manifest-good.txt)"
expect fail "геолокация ловится" check_no_extra_permissions "$(read_fixture manifest-permissions.txt)"
expect pass "открытый HTTP выключен" check_no_cleartext "$(read_fixture manifest-good.txt)"

echo "== вшитый адрес узла"
expect pass "адрес без секретов проходит" check_node_resource "$(read_fixture node-good.json)"
expect fail "лишнее поле не проходит" check_node_resource "$(read_fixture node-with-token.json)"
expect fail "отсутствие ресурса не проходит" check_node_resource ""

# Секрет из отвергнутого ресурса не должен появляться в выводе проверки: иначе
# страховка от вшитого секрета сама разносит его по логам сборки.
checks=$((checks + 1))
leak="$(check_node_resource "$(read_fixture node-with-token.json)" 2>&1 || true)"
if grep -q 'SECRETVALUE' <<<"$leak"; then
    printf '  FAIL  секрет утёк в вывод проверки: %s\n' "$leak" >&2
    failures=$((failures + 1))
else
    printf '  OK    секрет не попадает в вывод проверки\n'
fi

echo "== подпись"
EXPECTED="608e713c04a69a695fde298f315f59fdda4b9550d6a299a25aca553e6b294ab7"
expect pass "наш ключ проходит" check_signer "$(read_fixture signer-good.txt)" "$EXPECTED"
expect fail "чужой ключ не проходит" check_signer "$(read_fixture signer-other.txt)" "$EXPECTED"
expect fail "отладочный ключ не проходит" check_signer "$(read_fixture signer-debug.txt)" "$EXPECTED"
expect fail "неразобранный вывод не проходит" check_signer "" "$EXPECTED"

echo
if [[ $failures -eq 0 ]]; then
    echo "Все $checks проверок пройдены."
else
    echo "Провалено: $failures из $checks" >&2
    exit 1
fi
