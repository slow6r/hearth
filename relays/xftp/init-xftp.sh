#!/usr/bin/env bash
# Инициализация XFTP-релея. Один раз за жизнь узла.
#
# Как и у smp: отпечаток CA входит в адрес xftp://<fp>:<pass>@<host>:5443.
#
# ФЛАГИ СВЕРЕНЫ С v7.0.1 (`xftp-server init --help`). Предыдущая редакция скрипта
# передавала `-y` и `--password` — ни того, ни другого у этой версии нет, и скрипт
# падал на первой же строке. Пароль задаётся не флагом, а ключом `create_password`
# в ini уже после init; ниже это и делается.
set -euo pipefail

NODE_HOST="${NODE_HOST:?укажите NODE_HOST=<домен или публичный IP> — то же, что node.host в hearthd.toml}"
SECRETS_DIR="${SECRETS_DIR:-/etc/hearth/secrets}"
PASSWORD_FILE="$SECRETS_DIR/xftp-create-password"
CONFIG_DIR="${CONFIG_DIR:-/etc/opt/simplex-xftp}"
INI="$CONFIG_DIR/file-server.ini"
FILES_DIR="${FILES_DIR:-/var/opt/simplex-xftp/files}"
QUOTA="${QUOTA:-150gb}"
PORT="${PORT:-5443}"
CONTROL_PORT="${CONTROL_PORT:-5444}"

if [[ -f "$INI" ]]; then
    echo "!! $INI уже существует — повторный init сменит адрес." >&2
    exit 1
fi

command -v xftp-server >/dev/null || { echo "xftp-server не найден в PATH" >&2; exit 1; }
command -v openssl     >/dev/null || { echo "openssl не найден в PATH" >&2; exit 1; }

install -d -m 0700 "$SECRETS_DIR"
install -d -m 0750 -o simplex -g simplex "$FILES_DIR" 2>/dev/null \
  || install -d -m 0750 "$FILES_DIR"
PASSWORD="$(openssl rand -hex 24)"

if [[ "$NODE_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    HOST_FLAG=(--ip "$NODE_HOST")
else
    HOST_FLAG=(--fqdn "$NODE_HOST")
fi

xftp-server init "${HOST_FLAG[@]}" --quota "$QUOTA" --path "$FILES_DIR"

# --- то, что init не умеет, а конфигурация требует -------------------------------
#
# ПОРТ. Дефолт, который генерирует v7.0.1, — 443. Тот самый, на котором уже стоит
# smp-server (`extra_ports = [443]`, ради пробивания ограниченных сетей). Оставить
# как есть — значит получить два сервера на одном порту: который поднимется вторым,
# упадёт с EADDRINUSE. Это не настройка на вкус, а обязательная правка.
#
# CONTROL PORT. Дефолт — 5226 и закомментирован. hearthd опрашивает 5444
# (`xftp.control` в hearthd.toml); без этой строки health-проверка XFTP всегда
# «control port is not responding».
#
# CREATE_PASSWORD. Флага нет, ключ закомментирован. На публично доступном сервере
# это единственное, что мешает посторонним использовать его как файлопомойку.
python3 - "$INI" "$PASSWORD" "$PORT" "$CONTROL_PORT" <<'PY'
import re, secrets, sys

ini, password, port, control_port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(ini, encoding="utf-8") as fh:
    s = fh.read()


def set_key(text, key, value, section_hint=None):
    """Set `key = value`, uncommenting the upstream template line if that is all there is."""
    live = re.compile(r"(?m)^(\s*)%s\s*=.*$" % re.escape(key))
    if live.search(text):
        return live.sub(lambda m: "%s%s = %s" % (m.group(1), key, value), text, count=1)
    commented = re.compile(r"(?m)^\s*#\s*%s\s*=.*$" % re.escape(key))
    if commented.search(text):
        return commented.sub("%s = %s" % (key, value), text, count=1)
    if section_hint is None:
        raise SystemExit("не нашёл, куда писать %s" % key)
    anchor = re.compile(r"(?m)^\[%s\]\s*$" % re.escape(section_hint))
    m = anchor.search(text)
    if not m:
        raise SystemExit("нет секции [%s] для %s" % (section_hint, key))
    return text[: m.end()] + "\n%s = %s" % (key, value) + text[m.end():]


s = set_key(s, "create_password", password, "AUTH")
# Пароли control port. smp-server генерирует их сам при `--control-port`; у xftp
# ключи остаются закомментированными, то есть control port принимал бы команды без
# проверки. Он на loopback, но незачем.
s = set_key(s, "control_port_admin_password", secrets.token_hex(16), "AUTH")
s = set_key(s, "control_port_user_password", secrets.token_hex(16), "AUTH")
s = set_key(s, "port", port, "TRANSPORT")
s = set_key(s, "control_port", control_port, "TRANSPORT")
s = set_key(s, "prometheus_interval", "60", "STORE_LOG")
s = set_key(s, "log_stats", "off", "STORE_LOG")
s = set_key(s, "expire_files_hours", "168", "STORE_LOG")
s = set_key(s, "log_tls_errors", "off", "TRANSPORT")

with open(ini, "w", encoding="utf-8") as fh:
    fh.write(s)
print("ini: port=%s control_port=%s, create_password задан" % (port, control_port))
PY

umask 077
printf '%s\n' "$PASSWORD" > "$PASSWORD_FILE"
# hearthd читает пароль для сборки bundle — см. комментарий в init-smp.sh.
chown hearth:hearth "$PASSWORD_FILE" 2>/dev/null || true
chmod 0600 "$PASSWORD_FILE"
unset PASSWORD

chown -R simplex:simplex "$CONFIG_DIR" "$FILES_DIR" 2>/dev/null || true
chmod -R g+rX "$CONFIG_DIR" 2>/dev/null || true
# В ini лежит пароль на загрузку — группе его читать незачем.
chmod 0600 "$INI" 2>/dev/null || true
chown simplex:simplex "$INI" 2>/dev/null || true

cat <<NEXT

OK. Дальше:
  1. ./verify-ini-keys.sh $INI xftp/file-server.ini.example
     Особое внимание: port = $PORT (НЕ 443 — там smp) и control_port = $CONTROL_PORT.
  2. Пароль на загрузку — в $PASSWORD_FILE (0600 hearth:hearth). На публичном сервере
     это единственное, что мешает посторонним использовать его как хранилище.
  3. systemctl enable --now xftp-server && hearthctl health
NEXT
