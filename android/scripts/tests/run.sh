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
# shellcheck source=../lib/test-freshness.sh
source "$HERE/../lib/test-freshness.sh"

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

echo "== звонки: публичные STUN/TURN (патч 0004)"
# Главный случай — не «нашли адрес», а «не нашли собственное объяснение». Патч 0004
# ОБЪЯСНЯЕТ себя комментарием, который называет оба публичных сервера по именам,
# поэтому наивный grep по имени хоста валит вычищенный файл. Такой гейт выключают в
# первый же вечер, и вместе с ним перестаёт работать настоящая проверка.
expect pass "вычищенный call.js проходит, хотя хосты названы в комментарии"     check_no_public_ice "$(read_fixture call-js-hearth.txt)" "call.js"
expect fail "upstream-овский call.js не проходит"     check_no_public_ice "$(read_fixture call-js-upstream.txt)" "call.js"
expect fail "публичный STUN Google не проходит"     check_no_public_ice "$(read_fixture call-js-google.txt)" "call.js"
expect fail "исходник call.ts с публичными серверами не проходит"     check_no_public_ice "$(read_fixture call-ts-upstream.txt)" "call.ts"
expect pass "вычищенный call.ts проходит"     check_no_public_ice "$(read_fixture call-ts-hearth.txt)" "call.ts"
expect fail "пустой ввод не проходит" check_no_public_ice "" "call.js"
# Точка в имени хоста — метасимвол grep -E. Пока она не экранировалась, СВОЙ адрес,
# в котором на месте точек стоят дефисы, совпадал с шаблоном публичного сервера:
# гейт заворачивал честную сборку, то есть релиз не доходил до семьи.
expect pass "свой адрес, похожий на публичный только точками, проходит"     check_no_public_ice "$(read_fixture call-js-lookalike.txt)" "call.js"

echo "== звонки: запасной список ICE обязан быть пуст"
expect pass "пустой список проходит"     check_ice_defaults_empty "$(read_fixture call-js-hearth.txt)" "call.js"
expect pass "пустой список в TypeScript-форме проходит"     check_ice_defaults_empty "$(read_fixture call-ts-hearth.txt)" "call.ts"
expect fail "непустой список не проходит"     check_ice_defaults_empty "$(read_fixture call-js-upstream.txt)" "call.js"
# Отдельно от «нашли публичный адрес»: любой НЕ наш сервер в запасном списке — та же
# утечка, даже если его имени нет ни в одном чёрном списке.
expect fail "непубличный, но непустой список тоже не проходит"     check_ice_defaults_empty "$(read_fixture call-js-google.txt)" "call.js"
# Пропавшее объявление — это «патч больше не на месте», а не «всё хорошо»: так
# выглядит ребейз, после которого call.js перестроили по-другому.
expect fail "пропавшее объявление не проходит"     check_ice_defaults_empty "$(read_fixture call-js-no-decl.txt)" "call.js"
expect fail "пустой ввод не проходит" check_ice_defaults_empty "" "call.js"

echo "== ресурсы подписи обновлений (ADR 0014)"
# Гейт ЗАЯВЛЯЛ, что не пропустит сборку, объявившую себя неподписываемой, но проверял
# это подстрочным grep прямо в verify-apk.sh, и ни одной фикстуры под ним не было.
# Заявление без доказательства — это и есть защита на словах.
expect pass "обычная сборка проходит"                       check_no_unsigned_updates_flag "$(read_fixture resources-good.txt)"
expect fail "объявленный отказ от подписи валит релиз"      check_no_unsigned_updates_flag "$(read_fixture resources-unsigned-flag.txt)"
expect fail "флаг рядом с ключом валит релиз тоже"          check_no_unsigned_updates_flag "$(read_fixture resources-key-and-flag.txt)"
# Неразобранная таблица — это неизвестность, а не чистота: пустой ввод проходил обе
# проверки, то есть сломанный aapt2 выглядел как безупречная сборка.
expect fail "пустая таблица ресурсов не проходит"           check_no_unsigned_updates_flag ""
expect pass "ключ подписи на месте"                         check_release_key_present "$(read_fixture resources-good.txt)"
expect fail "сборка без ключа не проходит"                  check_release_key_present "$(read_fixture resources-unsigned-flag.txt)"
expect fail "пустая таблица ресурсов не проходит"           check_release_key_present ""
# Имя сравнивается целиком. Подстрочный grep считал `hearth_release_key_backup` за
# вшитый ключ — то есть сборку БЕЗ ключа можно было провести через гейт, положив рядом
# похоже названный файл; и наоборот, `..._disabled` он засчитывал за отказ от подписи.
expect fail "похожее имя за ключ не считается"              check_release_key_present "$(read_fixture resources-lookalike.txt)"
expect pass "похожее имя за отказ от подписи не считается"  check_no_unsigned_updates_flag "$(read_fixture resources-lookalike.txt)"

echo "== подпись"
EXPECTED="608e713c04a69a695fde298f315f59fdda4b9550d6a299a25aca553e6b294ab7"
expect pass "наш ключ проходит" check_signer "$(read_fixture signer-good.txt)" "$EXPECTED"
expect fail "чужой ключ не проходит" check_signer "$(read_fixture signer-other.txt)" "$EXPECTED"
expect fail "отладочный ключ не проходит" check_signer "$(read_fixture signer-debug.txt)" "$EXPECTED"
expect fail "неразобранный вывод не проходит" check_signer "" "$EXPECTED"

echo "== свежесть результатов тестов"
# Случай, из-за которого проверка и появилась: Gradle вернул UP-TO-DATE, XML
# остались от прошлого раза, и зелёная сводка описывает прогон, которого не было.
freshness_case() {
    local d mark rc=0
    d="$(mktemp -d)"
    mark="$d/mark"
    case "$1" in
        fresh)   : > "$mark"; sleep 1; : > "$d/TEST-a.xml" ;;
        stale)   : > "$d/TEST-a.xml"; sleep 1; : > "$mark" ;;
        partial) : > "$d/TEST-old.xml"; sleep 1; : > "$mark"; sleep 1; : > "$d/TEST-new.xml" ;;
        empty)   : > "$mark" ;;
    esac
    fresh_results "$mark" "$d" || rc=1
    rm -f "$d"/TEST-*.xml "$mark"
    rmdir "$d"
    return $rc
}
expect pass "XML новее метки — прогон состоялся"                  freshness_case fresh
expect fail "XML старше метки (UP-TO-DATE) — прогона не было"     freshness_case stale
expect fail "часть XML от прошлого раза — тоже не прогон"         freshness_case partial
expect fail "результатов нет вовсе — не прогон"                   freshness_case empty
expect fail "нет каталога результатов — не прогон"                fresh_results "$HERE/run.sh" "$HERE/нет-такого-каталога"

echo
if [[ $failures -eq 0 ]]; then
    echo "Все $checks проверок пройдены."
else
    echo "Провалено: $failures из $checks" >&2
    exit 1
fi
