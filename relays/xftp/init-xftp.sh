#!/usr/bin/env bash
# Инициализация XFTP-релея. Один раз за жизнь узла.
#
# Как и у smp: отпечаток CA входит в адрес xftp://<fp>:<pass>@<host>:5443.
set -euo pipefail

NODE_HOST="${NODE_HOST:?укажите NODE_HOST=<домен или публичный IP> — то же, что node.host в hearthd.toml}"
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
install -d -m 0750 -o xftp -g xftp "$FILES_DIR" 2>/dev/null \
  || install -d -m 0750 "$FILES_DIR"
PASSWORD="$(openssl rand -hex 24)"

if [[ "$NODE_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    HOST_FLAG=(--ip "$NODE_HOST")
else
    HOST_FLAG=(--fqdn "$NODE_HOST")
fi

# Флаги сверить с `xftp-server init --help` пинованной версии.
xftp-server init -y "${HOST_FLAG[@]}" --quota "$QUOTA" --path "$FILES_DIR" --password "$PASSWORD"

umask 077
printf '%s\n' "$PASSWORD" > "$PASSWORD_FILE"
chmod 0600 "$PASSWORD_FILE"
unset PASSWORD

cat <<NEXT

OK. Дальше:
  1. ./verify-ini-keys.sh $CONFIG_DIR/file-server.ini xftp/file-server.ini.example
  2. Пароль на загрузку — в $PASSWORD_FILE (0600). На публичном сервере это
     единственное, что мешает посторонним использовать его как хранилище.
  3. systemctl enable --now xftp-server && hearthctl health
NEXT
