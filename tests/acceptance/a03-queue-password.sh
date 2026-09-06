#!/usr/bin/env bash
# A3 — создание очереди без пароля отвергается (ТЗ §6.2, §12).
#
# Полная проверка делается с клиента (добавить сервер без пароля и попробовать создать
# контакт). Здесь — необходимые условия: пароль задан в ini и файл секрета на месте.
set -uo pipefail

SMP_INI="${SMP_INI:-/etc/opt/simplex/smp-server.ini}"
XFTP_INI="${XFTP_INI:-/etc/opt/simplex-xftp/file-server.ini}"
SECRETS="${SECRETS:-/etc/hearth/secrets}"

status=0

check_ini() {
    local ini="$1" name="$2"
    if [[ ! -f "$ini" ]]; then
        echo "  ?  $name: $ini не найден (релей инициализирован?)"
        return 0
    fi
    if grep -qE '^[[:space:]]*create_password[[:space:]]*[:=][[:space:]]*.+' "$ini"; then
        echo "  ok $name: create_password задан"
    else
        echo "  !! $name: create_password отсутствует или пуст — очередь создаст кто угодно из WG"
        status=1
    fi
}

check_secret() {
    local file="$1" name="$2"
    if [[ ! -f "$file" ]]; then
        echo "  !! $name: нет файла секрета $file — hearthd не соберёт bundle"
        status=1
        return
    fi
    if [[ ! -s "$file" ]]; then
        echo "  !! $name: файл секрета пуст"
        status=1
        return
    fi
    local mode
    mode="$(stat -c '%a' "$file" 2>/dev/null || echo '?')"
    if [[ "$mode" == "600" ]]; then
        echo "  ok $name: секрет на месте, права 0600"
    else
        echo "  !! $name: права $mode вместо 0600 на $file"
        status=1
    fi
}

check_ini "$SMP_INI" smp
check_ini "$XFTP_INI" xftp
check_secret "$SECRETS/smp-create-password" smp
check_secret "$SECRETS/xftp-create-password" xftp

echo
echo "  Полная проверка A3 — с устройства: добавить smp://<fp>@10.66.10.10:5223"
echo "  (без пароля) и попытаться создать контакт. Ожидание: отказ."
exit $status
