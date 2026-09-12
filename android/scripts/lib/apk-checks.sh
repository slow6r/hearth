#!/usr/bin/env bash
# Разбор вывода Android-инструментов — отдельно от их запуска.
#
# # Зачем библиотека
#
# Проверки APK раньше жили прямо в теле `verify-apk.sh` и работали грепом по
# подстроке. Проверить их можно было только настоящим APK — то есть никогда, потому
# что для отрицательного случая нужен заведомо плохой APK, которого ни у кого нет.
# Результат предсказуем: проверка `allowBackup` совпадала с идентификатором самого
# атрибута и печатала «OK allowBackup=false» при `allowBackup=true`.
#
# Здесь только чистые функции над текстом. Их гоняет `tests/run.sh` по фикстурам —
# сохранённым кускам настоящего вывода `aapt2`, включая заведомо плохие.
#
# Договор функций: 0 — проверка пройдена, 1 — провалена, сообщение печатается в
# stdout. Ни одна из них не запускает инструменты и не трогает файлы.

# Значение атрибута из `aapt2 dump xmltree`.
#
# Строка выглядит так:
#   A: http://schemas.android.com/apk/res/android:allowBackup(0x0101000b)=true
# Берём то, что ПОСЛЕ знака равенства, а не ищем подстроку: именно подстрока
# `allowBackup(0x0` когда-то совпадала с идентификатором атрибута и снимала отказ.
apk_attr_value() {
    local manifest="$1" name="$2"
    # Берём до конца строки, а не до первого пробела: булево aapt2 печатает как
    # `(type 0x12)0x0` — с пробелом внутри самого значения.
    printf '%s\n' "$manifest" \
        | grep -oE "${name}\([^)]*\)=.*$" \
        | head -1 \
        | sed -E 's/^[^=]*=//; s/[[:space:]]+$//' \
        | tr -d '\r'
}

# Нормализовать булево значение: aapt2 печатает его в нескольких формах.
apk_bool() {
    printf '%s' "$1" | sed -E 's/^\(type 0x[0-9a-f]+\)//' | tr -d '\r'
}

apk_is_false() {
    case "$(apk_bool "$1")" in
        false | 0x0 | 0x00000000 | 0) return 0 ;;
        *) return 1 ;;
    esac
}

# Бэкапы ОС обязаны быть выключены (ТЗ §8.2 п.6, A9).
#
# Отсутствие атрибута — это отказ, а не «наверное, нормально»: по умолчанию Android
# считает allowBackup включённым, и потерянный при ребейзе `tools:replace` выглядел
# бы именно так.
check_allow_backup() {
    local manifest="$1"
    local raw
    raw="$(apk_attr_value "$manifest" allowBackup)"
    if [[ -z "$raw" ]]; then
        echo "атрибут allowBackup не найден; по умолчанию Android считает его true"
        return 1
    fi
    if apk_is_false "$raw"; then
        echo "allowBackup=$raw"
        return 0
    fi
    echo "allowBackup=$raw — база чата уйдёт в бэкап ОС"
    return 1
}

# Релизная сборка не должна быть отлаживаемой: иначе `adb run-as` читает базу и
# ключи с устройства без root.
check_not_debuggable() {
    local manifest="$1"
    local raw
    raw="$(apk_attr_value "$manifest" debuggable)"
    if [[ -z "$raw" ]] || apk_is_false "$raw"; then
        echo "debuggable не выставлен"
        return 0
    fi
    echo "APK собран с отладкой (debuggable=$raw)"
    return 1
}

# Открытый HTTP запрещён.
check_no_cleartext() {
    local manifest="$1"
    local raw
    raw="$(apk_attr_value "$manifest" usesCleartextTraffic)"
    if [[ -z "$raw" ]] || apk_is_false "$raw"; then
        echo "usesCleartextTraffic не включён"
        return 0
    fi
    echo "usesCleartextTraffic=$raw"
    return 1
}

# Доверие к CA узла подключается только через network security config: без него
# device API недостижим, а значит и обновления, и заведение по коду.
check_network_security_config() {
    local manifest="$1"
    local raw
    raw="$(apk_attr_value "$manifest" networkSecurityConfig)"
    if [[ -z "$raw" ]]; then
        echo "networkSecurityConfig не применён — узел не будет доверенным"
        return 1
    fi
    echo "networkSecurityConfig=$raw"
    return 0
}

# Правила извлечения данных должны ссылаться на ресурс, а не просто упоминаться.
check_data_extraction_rules() {
    local manifest="$1"
    local raw
    raw="$(apk_attr_value "$manifest" dataExtractionRules)"
    if [[ "$raw" =~ ^@0x[0-9a-f]+$ ]] || [[ "$raw" == *hearth_data_extraction_rules* ]]; then
        echo "dataExtractionRules=$raw"
        return 0
    fi
    echo "dataExtractionRules не задан ссылкой на ресурс (значение: ${raw:-пусто})"
    return 1
}

# Метка testOnly ставится AGP при сборке «из IDE на устройство». Такой APK
# подписывается и проходит все прочие проверки, но обычная установка невозможна.
check_not_test_only() {
    local manifest="$1"
    if printf '%s\n' "$manifest" | grep -qi 'testOnly'; then
        echo "APK помечен testOnly — обычная установка невозможна"
        return 1
    fi
    echo "testOnly не выставлен"
    return 0
}

# Лишние разрешения: FCM и геолокация в этой сборке существовать не могут.
check_no_extra_permissions() {
    local manifest="$1"
    if printf '%s\n' "$manifest" | grep -qiE 'c2dm|FOREGROUND_SERVICE_LOCATION|ACCESS_FINE_LOCATION'; then
        echo "в манифесте есть лишние разрешения (FCM/геолокация)"
        return 1
    fi
    echo "лишних разрешений нет"
    return 0
}

# Вшитый адрес узла: ровно два поля и никаких секретов.
#
# Значения НЕ печатаются целиком при отказе: проверка, задуманная как страховка от
# вшитого секрета, не должна сама разносить его по логам сборки и скриншотам.
check_node_resource() {
    local json="$1"
    if [[ -z "$json" ]]; then
        echo "в сборке нет ресурса raw/hearth_node — вместо ввода кода покажется сканер QR"
        return 1
    fi
    local keys
    keys="$(printf '%s' "$json" | grep -oE '"[a-zA-Z_]+"[[:space:]]*:' | tr -d '":' | tr -d ' ' | sort | tr '\n' ',')"
    if [[ "$keys" != "host,port," ]]; then
        echo "в hearth_node.json посторонние поля (${keys%,}) — секрету в сборке не место"
        return 1
    fi
    local host port
    host="$(printf '%s' "$json" | grep -oE '"host"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"host"[[:space:]]*:[[:space:]]*"//; s/"$//')"
    port="$(printf '%s' "$json" | grep -oE '"port"[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+$')"
    if [[ -z "$host" || -z "$port" ]]; then
        echo "адрес узла не разобран"
        return 1
    fi
    if ((${#host} > 253)); then
        echo "хост подозрительно длинный"
        return 1
    fi
    echo "адрес узла вшит: host=$host port=$port"
    return 0
}

# Отпечаток подписи сверяется с закреплённым, а не печатается для сверки глазами.
check_signer() {
    local output="$1" expected="$2"
    local actual
    actual="$(printf '%s\n' "$output" | grep -iA0 'Signer #1 certificate SHA-256 digest' | grep -oE '[0-9a-f]{64}' | head -1)"
    if [[ -z "$actual" ]]; then
        echo "отпечаток подписи не разобран"
        return 1
    fi
    if printf '%s\n' "$output" | grep -q 'CN=Android Debug'; then
        echo "APK подписан отладочным ключом"
        return 1
    fi
    if [[ "$actual" != "$expected" ]]; then
        echo "отпечаток подписи не совпал: ожидался $expected, получен $actual"
        return 1
    fi
    echo "подпись тем же ключом ($actual)"
    return 0
}
