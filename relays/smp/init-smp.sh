#!/usr/bin/env bash
# Инициализация SMP-релея (ТЗ §6.2). Запускается ОДИН РАЗ за жизнь узла.
#
# Создаёт CA релея, ключи и fingerprint в /etc/opt/simplex. Отпечаток этого CA входит
# в адрес smp://<fp>:<pass>@10.66.10.10:5223 — то есть повторный init означает новый
# адрес и ручную перенастройку всех контактов у всех членов семьи. Скрипт на это молча
# не согласится.
set -euo pipefail

NODE_IP="${NODE_IP:-10.66.10.10}"
SECRETS_DIR="${SECRETS_DIR:-/etc/hearth/secrets}"
PASSWORD_FILE="$SECRETS_DIR/smp-create-password"
CONFIG_DIR="${CONFIG_DIR:-/etc/opt/simplex}"

if [[ -f "$CONFIG_DIR/smp-server.ini" ]]; then
    echo "!! $CONFIG_DIR/smp-server.ini уже существует." >&2
    echo "   Повторная инициализация сменит отпечаток CA и сломает адрес релея." >&2
    echo "   Если это действительно нужно — docs/runbook-rotate-address.md." >&2
    exit 1
fi

command -v smp-server >/dev/null || { echo "smp-server не найден в PATH" >&2; exit 1; }
command -v openssl    >/dev/null || { echo "openssl не найден в PATH" >&2; exit 1; }

install -d -m 0700 "$SECRETS_DIR"
PASSWORD="$(openssl rand -hex 24)"

# Флаги сверить с пинованной версией: smp-server init --help
#   -y   без интерактивных вопросов
#   -l   включить store log
#   --ip адрес, попадающий в сертификат и в адрес сервера
smp-server init -y -l --ip "$NODE_IP" --password "$PASSWORD"

umask 077
printf '%s\n' "$PASSWORD" > "$PASSWORD_FILE"
chmod 0600 "$PASSWORD_FILE"
unset PASSWORD

echo
echo "OK. Дальше:"
echo "  1. Привести $CONFIG_DIR/smp-server.ini к требованиям ТЗ §6.2:"
echo "     ./verify-ini-keys.sh $CONFIG_DIR/smp-server.ini smp/smp-server.ini.example"
echo "  2. Пароль лежит в $PASSWORD_FILE (0600) — оттуда его читает hearthd для bundle."
echo "  3. Отпечаток CA: $CONFIG_DIR/fingerprint — это часть адреса релея."
echo "  4. systemctl enable --now smp-server && hearthctl health"
