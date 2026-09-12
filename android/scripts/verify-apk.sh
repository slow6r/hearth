#!/usr/bin/env bash
# Проверка собранного APK перед раздачей (ТЗ §8.3, acceptance A5, A9; ADR 0012).
#
#   ./verify-apk.sh path/to/hearth-release.apk
#
# Ловит регрессы, которые проще всего внести случайно при ребейзе на новый
# upstream-тег: подтянулась зависимость с Play Services, вернулся allowBackup,
# сборка помечена testOnly, в дефолтах опять публичный релей, в ресурс попал секрет.
#
# # Почему гейт падает от ошибки инструмента
#
# Раньше захваты выглядели как `X="$(tool ... || true)"`, и недоступный apkanalyzer,
# другая версия build-tools или битый zip давали ПУСТОЙ ввод всем проверкам — а
# пустой ввод проходил их все. Состояние «инструмент сломался» было неотличимо от
# «всё чисто»: человек видел сплошные OK и раздавал сборку, которую никто не смотрел.
# Поэтому здесь любая осечка инструмента — немедленный выход с кодом 2, а каждый
# захват проверяется на осмысленность, а не только на непустоту.
#
# Разбор вынесен в lib/apk-checks.sh и проверяется фикстурами: ./tests/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/apk-checks.sh
source "$HERE/lib/apk-checks.sh"

APK="${1:?usage: verify-apk.sh <apk>}"
[[ -f "$APK" ]] || { echo "нет файла: $APK" >&2; exit 1; }

failures=0
pass() { printf '  OK    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }
need() { command -v "$1" >/dev/null || { echo "нет утилиты $1 (Android SDK build-tools / cmdline-tools)" >&2; exit 2; }; }

# Инструмент, который не отработал, останавливает проверку целиком.
run_or_die() {
    local out
    if ! out="$("$@" 2>&1)"; then
        echo "инструмент не отработал: $*" >&2
        printf '%s\n' "$out" >&2
        exit 2
    fi
    printf '%s' "$out"
}

# Захват обязан быть не только непустым, но и похожим на то, что мы просили.
expect_marker() {
    local text="$1" marker="$2" what="$3"
    if ! grep -q "$marker" <<<"$text"; then
        echo "вывод $what не похож на ожидаемый (нет «$marker») — проверка недостоверна" >&2
        exit 2
    fi
}

# reporter <описание-по-умолчанию> <функция> <аргументы...>
check() {
    local out rc
    out="$("$@" 2>&1)"
    rc=$?
    if [[ $rc -eq 0 ]]; then pass "$out"; else fail "$out"; fi
}

for tool in apkanalyzer aapt2 apksigner unzip strings; do need "$tool"; done

echo "== A5: никаких Google/Firebase SDK (ТЗ §8.3)"
PACKAGES="$(run_or_die apkanalyzer dex packages "$APK")"
expect_marker "$PACKAGES" 'chat.simplex' "apkanalyzer dex packages"
for forbidden in \
    "com.google.android.gms" \
    "com.google.firebase" \
    "com.google.android.play" \
    "com.crashlytics" \
    "io.sentry" \
    "com.appsflyer" \
    "com.amplitude"
do
    if grep -q "$forbidden" <<<"$PACKAGES"; then
        fail "в dex найден $forbidden"
    else
        pass "нет $forbidden"
    fi
done

echo
echo "== A9 / ТЗ §8.2 п.6: манифест"
MANIFEST="$(run_or_die aapt2 dump xmltree --file AndroidManifest.xml "$APK")"
expect_marker "$MANIFEST" 'E: manifest' "aapt2 dump xmltree"
check check_allow_backup "$MANIFEST"
check check_data_extraction_rules "$MANIFEST"
check check_not_debuggable "$MANIFEST"
check check_no_cleartext "$MANIFEST"
check check_network_security_config "$MANIFEST"
check check_not_test_only "$MANIFEST"
check check_no_extra_permissions "$MANIFEST"

echo
echo "== ТЗ §1.2 / §8.2: в НАШЕМ коде нет адресов публичной сети SimpleX"
# Только по dex. Нативное ядро — официальная сборка upstream, и строки публичных
# релеев в ней есть всегда: убрать их можно только пересобрав Haskell, чего мы не
# делаем. Поэтому ядро сверяется по хешу ниже, а не по строкам, и заголовок говорит
# правду — иначе вывод скрипта обещает больше, чем проверяет.
STRINGS="$(unzip -p "$APK" 'classes*.dex' | strings)"
if [[ ${#STRINGS} -lt 100000 ]]; then
    echo "dex разобран подозрительно коротко (${#STRINGS} байт) — проверка недостоверна" >&2
    exit 2
fi
for host in "smp1.simplex.im" "smp8.simplex.im" "xftp1.simplex.im" "ntf1.simplex.im" "stun.l.google.com"; do
    if grep -qF "$host" <<<"$STRINGS"; then
        fail "в dex найдена строка $host"
    else
        pass "нет $host"
    fi
done

echo
echo "== Нативное ядро: ровно то, что выпустил upstream"
PINS="$HERE/native-libs.sha256"
if [[ -f "$PINS" ]]; then
    tmp_libs="$(mktemp -d)"
    trap 'rm -rf "$tmp_libs"' EXIT
    while read -r expected name; do
        [[ -n "$expected" ]] || continue
        if ! unzip -p "$APK" "lib/arm64-v8a/$name" > "$tmp_libs/$name" 2>/dev/null; then
            fail "в APK нет lib/arm64-v8a/$name"
            continue
        fi
        actual="$(sha256sum "$tmp_libs/$name" | cut -d' ' -f1)"
        if [[ "$actual" == "$expected" ]]; then
            pass "$name совпадает с пинованным хешем"
        else
            fail "$name НЕ совпадает: ожидался $expected, получен $actual"
        fi
    done < "$PINS"
else
    fail "нет $PINS — нативное ядро не сверено (создайте: см. android/FORK.md)"
fi

echo
echo "== ADR 0012: в сборке адрес узла и НИ ОДНОГО секрета"
RES_TABLE="$(run_or_die aapt2 dump resources "$APK")"
expect_marker "$RES_TABLE" 'Package name=' "aapt2 dump resources"
NODE_PATH="$(grep -A1 'raw/hearth_node$' <<<"$RES_TABLE" | grep -oE 'res/[^ ]+' | head -1 || true)"
NODE_RES=""
if [[ -n "$NODE_PATH" ]]; then
    NODE_RES="$(unzip -p "$APK" "$NODE_PATH" 2>/dev/null || true)"
fi
check check_node_resource "$NODE_RES"
if grep -q 'raw/hearth_invite' <<<"$RES_TABLE"; then
    fail "остался ресурс raw/hearth_invite — это вшитый секрет (ADR 0012)"
else
    pass "старого приглашения в сборке нет"
fi

echo
echo "== Подпись (ТЗ §8.4: ключ офлайновый, подпись — ручной шаг)"
SIGNER_FILE="$HERE/signer.sha256"
EXPECTED_SIGNER="${HEARTH_SIGNER_SHA256:-}"
if [[ -z "$EXPECTED_SIGNER" && -f "$SIGNER_FILE" ]]; then
    EXPECTED_SIGNER="$(tr -d ' \t\r\n' < "$SIGNER_FILE")"
fi
if [[ -z "$EXPECTED_SIGNER" ]]; then
    echo "не задан эталон подписи ($SIGNER_FILE или HEARTH_SIGNER_SHA256)" >&2
    exit 2
fi
SIGNER_OUT="$(run_or_die apksigner verify --print-certs "$APK")"
check check_signer "$SIGNER_OUT" "$EXPECTED_SIGNER"

echo
echo "== ABI (ТЗ §8.4: только arm64-v8a в релизе)"
LIBS="$(unzip -l "$APK" | awk '/lib\// {print $4}' | cut -d/ -f2 | sort -u)"
if [[ -z "$LIBS" ]]; then
    fail "в APK нет нативных библиотек — это точно релизная сборка?"
elif [[ "$LIBS" == "arm64-v8a" ]]; then
    pass "только arm64-v8a"
else
    fail "лишние ABI: $(tr '\n' ' ' <<<"$LIBS")"
fi

echo
if [[ $failures -eq 0 ]]; then
    echo "Все проверки пройдены."
else
    echo "Провалено проверок: $failures" >&2
    exit 1
fi
