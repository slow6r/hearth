#!/usr/bin/env bash
# Проверка собранного APK на соответствие ТЗ §8.3 и acceptance-тестам A5, A9.
#
#   ./verify-apk.sh path/to/hearth-release.apk
#
# Ловит ровно те регрессы, которые проще всего внести случайно при ребейзе на новый
# upstream-тег: подтянулась зависимость с Play Services, вернулся allowBackup,
# в дефолтах опять появился публичный релей.
#
# Требует Android SDK build-tools (apkanalyzer, aapt2, apksigner) в PATH.
set -euo pipefail

APK="${1:?usage: verify-apk.sh <apk>}"
[[ -f "$APK" ]] || { echo "нет файла: $APK" >&2; exit 1; }

failures=0
pass() { printf '  OK    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; failures=$((failures + 1)); }
need() { command -v "$1" >/dev/null || { echo "нет утилиты $1 (Android SDK build-tools)" >&2; exit 2; }; }

need apkanalyzer

echo "== A5: никаких Google/Firebase SDK (ТЗ §8.3)"
PACKAGES="$(apkanalyzer dex packages "$APK" 2>/dev/null || true)"
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
echo "== A9 / ТЗ §8.2 п.6: бэкапы ОС выключены"
if command -v aapt2 >/dev/null; then
    MANIFEST="$(aapt2 dump xmltree --file AndroidManifest.xml "$APK" 2>/dev/null || true)"
    if grep -q 'allowBackup.*=.*false\|allowBackup.*(0x0)=false\|allowBackup.*0x0' <<<"$MANIFEST"; then
        pass "allowBackup=false"
    else
        fail "allowBackup не выключен (или не найден в манифесте)"
    fi
    if grep -q 'dataExtractionRules' <<<"$MANIFEST"; then
        pass "dataExtractionRules задан"
    else
        fail "dataExtractionRules отсутствует"
    fi
    if grep -qi 'c2dm\|FOREGROUND_SERVICE_LOCATION\|ACCESS_FINE_LOCATION' <<<"$MANIFEST"; then
        fail "в манифесте есть лишние разрешения (FCM/геолокация)"
    else
        pass "лишних разрешений нет"
    fi
    # testOnly ставит AGP, когда сборку зовут с -Pandroid.injected.* — это режим
    # «деплой из IDE». Такой APK подписывается и проходит все прочие проверки, но
    # Android отказывается его ставить: «приложение предназначено только для
    # тестирования». Ошибка обязана всплывать здесь, а не у человека в руках.
    if grep -qi 'testOnly' <<<"$MANIFEST"; then
        fail "APK помечен testOnly — обычная установка невозможна (см. patches/0012)"
    else
        pass "testOnly не выставлен"
    fi
else
    fail "aapt2 недоступен — проверка манифеста пропущена"
fi

echo
echo "== ТЗ §1.2 / §8.2: в сборке нет адресов публичной сети SimpleX"
STRINGS="$(unzip -p "$APK" 'classes*.dex' 2>/dev/null | strings 2>/dev/null || true)"
for host in "smp1.simplex.im" "smp8.simplex.im" "xftp1.simplex.im" "ntf1.simplex.im" "stun.l.google.com"; do
    if grep -qF "$host" <<<"$STRINGS"; then
        fail "в dex найдена строка $host"
    else
        pass "нет $host"
    fi
done

echo
echo "== ADR 0012: в сборке адрес узла и НИ ОДНОГО секрета"
# Ресурс ищется ПО ИМЕНИ, а не по пути в архиве: в релизе aapt2 укорачивает пути
# (res/raw/hearth_node.json становится res/o_.json), и проверка по пути врёт про
# исправную сборку. Приложение ищет тем же способом — через имя ресурса.
if command -v aapt2 >/dev/null; then
    RES_TABLE="$(aapt2 dump resources "$APK" 2>/dev/null || true)"
    NODE_PATH="$(grep -A1 'raw/hearth_node$' <<<"$RES_TABLE" | grep -oE 'res/[^ ]+' | head -1)"
    if [[ -n "$NODE_PATH" ]]; then
        NODE_RES="$(unzip -p "$APK" "$NODE_PATH" 2>/dev/null || true)"
        pass "адрес узла вшит ($NODE_PATH): $(tr -d '
' <<<"$NODE_RES")"
    else
        NODE_RES=""
        fail "нет ресурса raw/hearth_node — вместо ввода кода покажется сканер QR"
    fi
    # Токен приглашения раньше ехал внутри APK, и файл сам по себе впускал в контур.
    # Теперь секрет приносит человек. Проверка стоит здесь, чтобы старый порядок не
    # вернулся молча — например, если кто-то воскресит bake-invite.sh из истории.
    if grep -qE '"token"[[:space:]]*:' <<<"$NODE_RES"; then
        fail "в адресе узла есть токен — секрету в сборке не место (ADR 0012)"
    else
        pass "токена в сборке нет"
    fi
    if grep -q 'raw/hearth_invite' <<<"$RES_TABLE"; then
        fail "остался ресурс raw/hearth_invite — это вшитый секрет (ADR 0012)"
    else
        pass "старого приглашения в сборке нет"
    fi
else
    fail "aapt2 недоступен — вшитый адрес узла не проверен"
fi

echo
echo "== Подпись (ТЗ §8.4: ключ офлайновый, подпись — ручной шаг)"
if command -v apksigner >/dev/null; then
    if apksigner verify --print-certs "$APK" >/tmp/hearth-signer.txt 2>&1; then
        pass "подпись валидна"
        echo "     отпечаток:"
        grep -i 'SHA-256 digest' /tmp/hearth-signer.txt | head -1 | sed 's/^/     /'
        echo "     сверьте его с известным отпечатком ключа подписи!"
    else
        fail "apksigner verify не прошёл"
    fi
    rm -f /tmp/hearth-signer.txt
else
    fail "apksigner недоступен — подпись не проверена"
fi

echo
echo "== ABI (ТЗ §8.4: только arm64-v8a в релизе)"
LIBS="$(unzip -l "$APK" | awk '/lib\// {print $4}' | cut -d/ -f2 | sort -u)"
if [[ -z "$LIBS" ]]; then
    fail "в APK нет нативных библиотек — это точно релизная сборка SimpleX?"
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
