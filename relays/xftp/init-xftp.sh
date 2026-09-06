#!/usr/bin/env bash
# Инициализация XFTP-релея (ТЗ §6.3). Один раз за жизнь узла.
#
# Как и у smp: отпечаток CA входит в адрес xftp://<fp>:<pass>@10.66.10.10:5443.
set -euo pipefail

NODE_IP="${NODE_IP:-10.66.10.10}"
SECRETS_DIR="${SECRETS_DIR:-/etc/hearth/secrets}"
PASSWORD_FILE="$SECRETS_DIR/xftp-create-password"
CONFIG_DIR="${CONFIG_DIR:-/etc/opt/simplex-xftp}"
FILES_DIR="${FILES_DIR:-/var/opt/simplex-xftp/files}"
QUOTA="${QUOTA:-32gb}"

if [[ -f "$CONFIG_DIR/file-server.ini" ]]; then
    echo "!! $CONFIG_DIR/file-server.ini уже существует — повторный init сменит адрес." >&2
    exit 1
fi

command -v xftp-server >/dev/null || { echo "xftp-server не найден в PATH" >&2; exit 1; }
command -v openssl     >/dev/null || { echo "openssl не найден в PATH" >&2; exit 1; }

install -d -m 0700 "$SECRETS_DIR"
install -d -m 0750 -o simplex -g simplex "$FILES_DIR"
PASSWORD="$(openssl rand -hex 24)"

# Флаги сверить с пинованной версией: xftp-server init --help
xftp-server init -y --ip "$NODE_IP" --quota "$QUOTA" --path "$FILES_DIR" --password "$PASSWORD"

umask 077
printf '%s\n' "$PASSWORD" > "$PASSWORD_FILE"
chmod 0600 "$PASSWORD_FILE"
unset PASSWORD

echo
echo "OK. Дальше:"
echo "  1. ./verify-ini-keys.sh $CONFIG_DIR/file-server.ini xftp/file-server.ini.example"
echo "  2. systemctl enable --now xftp-server && hearthctl health"
