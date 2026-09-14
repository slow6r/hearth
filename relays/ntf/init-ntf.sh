#!/usr/bin/env bash
# Инициализация push-сервера (ntf-server) для iOS-приложения. Один раз за жизнь узла.
#
# ADR 0016, docs/runbook-ntf.md. Как у smp и xftp, отпечаток CA входит в адрес
# ntf://<fp>@<host>:<port>. Отличие в том, куда этот адрес попадает: он ВШИВАЕТСЯ в
# сборку iOS-приложения. Повторный init = новый отпечаток = пуши молча перестают
# работать у всех установленных сборок, пока не выйдет новая. Скрипт на это молча не
# согласится.
#
# ФЛАГИ СВЕРЕНЫ С simplexmq v7.0.1 (Notifications/Server/Main.hs, Server/CLI.hs): init
# понимает --ip, --fqdn, --database, --schema, --pool-size, --sign-algorithm и
# --disable-store-log. Пароля у push-сервера нет вовсе.
#
# ХРАНИЛИЩЕ — PostgreSQL, и это не выбор. Исполняемый ntf-server в v7.0.1 собирается
# только с флагом server_postgres, токены и подписки живут в базе. Ключ `enable` в
# [STORE_LOG] по исходникам только печатается при старте.
set -euo pipefail

NODE_HOST="${NODE_HOST:?укажите NODE_HOST=<домен или публичный IP> — то же, что node.host в hearthd.toml}"
CONFIG_DIR="${CONFIG_DIR:-/etc/opt/simplex-ntf}"
LOG_DIR="${LOG_DIR:-/var/opt/simplex-ntf}"
INI="$CONFIG_DIR/ntf-server.ini"
# НЕ 443 и НЕ 5223: провайдер узла выбрасывает на них TLS-приветствие SimpleX
# (docs/deploy-fels-2026-09-09.md). 2053 — из двадцати проверенных там портов.
PORT="${PORT:-2053}"
CONTROL_PORT="${CONTROL_PORT:-5227}"
NTF_USER="${NTF_USER:-simplex-ntf}"
DB_NAME="${DB_NAME:-ntf_server_store}"
DB_SCHEMA="${DB_SCHEMA:-ntf_server}"
APNS_KEY="${APNS_KEY:-/etc/credstore/hearth-apns.p8}"
NTF_ENV="${NTF_ENV:-/etc/hearth/ntf.env}"
NTF_RESOLV="${NTF_RESOLV:-/etc/hearth/ntf-resolv.conf}"

if [[ -f "$INI" ]]; then
    echo "!! $INI уже существует." >&2
    echo "   Повторный init сменит отпечаток CA, и пуши перестанут работать у всех" >&2
    echo "   установленных сборок iOS. Если это действительно нужно — docs/runbook-ntf.md." >&2
    exit 1
fi

for cmd in ntf-server psql runuser python3; do
    command -v "$cmd" >/dev/null || { echo "$cmd не найден в PATH" >&2; exit 1; }
done
id -u "$NTF_USER" >/dev/null 2>&1 \
    || { echo "нет пользователя $NTF_USER — сначала hearthd/deploy/install.sh" >&2; exit 1; }
# Эти три значения подставляются в SQL. Проверяем здесь, а не надеемся на кавычки.
[[ "$NTF_USER" =~ ^[a-z][a-z0-9-]*$ ]] || { echo "NTF_USER: только [a-z0-9-]" >&2; exit 1; }
[[ "$DB_NAME" =~ ^[a-z_][a-z0-9_]*$ && "$DB_SCHEMA" =~ ^[a-z_][a-z0-9_]*$ ]] \
    || { echo "DB_NAME и DB_SCHEMA: только [a-z0-9_]" >&2; exit 1; }

# psql от postgres ругается, если текущий каталог ему недоступен (/root).
cd /

echo "== 1. PostgreSQL: роль, база, схема"
# Роль названа как системный пользователь службы: локальный вход в Debian — peer, то
# есть PostgreSQL сверяет имя роли с тем, кто подключается к сокету. Пароля нет, и
# хранить его негде не надо.
pg() { runuser -u postgres -- psql -v ON_ERROR_STOP=1 -qAtX "$@"; }
if [[ -z "$(pg -c "SELECT 1 FROM pg_roles WHERE rolname = '$NTF_USER'")" ]]; then
    pg -c "CREATE ROLE \"$NTF_USER\" LOGIN"
fi
if [[ -z "$(pg -c "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'")" ]]; then
    pg -c "CREATE DATABASE $DB_NAME OWNER \"$NTF_USER\""
fi
# Схему ntf-server сам не создаёт (createSchema = False в Server/CLI.hs, iniDBOptions) —
# только таблицы в ней.
runuser -u "$NTF_USER" -- psql -v ON_ERROR_STOP=1 -qX -d "$DB_NAME" \
    -c "CREATE SCHEMA IF NOT EXISTS $DB_SCHEMA"
DB_CONNECTION="postgresql://$NTF_USER@/$DB_NAME"

echo "== 2. ntf-server init"
if [[ "$NODE_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    HOST_FLAG=(--ip "$NODE_HOST")
else
    HOST_FLAG=(--fqdn "$NODE_HOST")
fi
install -d -m 0750 -o "$NTF_USER" -g "$NTF_USER" "$CONFIG_DIR" "$LOG_DIR"
# init ОЧИЩАЕТ оба каталога (clearDirIfExists) — содержимое, а не сами каталоги, поэтому
# точка монтирования /var/opt/simplex-ntf переживает его без вреда.
NTF_SERVER_CFG_PATH="$CONFIG_DIR" NTF_SERVER_LOG_PATH="$LOG_DIR" \
    ntf-server init "${HOST_FLAG[@]}" --database "$DB_CONNECTION" --schema "$DB_SCHEMA"

# --- то, что init оставляет в дефолте, а конфигурация требует иначе ---------------
#
# ПОРТ. Дефолт init — 443, на котором уже стоит smp-server и который режет провайдер.
# CONTROL PORT. Закомментирован; hearthd проверяет ntf.control из hearthd.toml.
# ПАРОЛИ CONTROL PORT. Закомментированы — порт принимал бы команды без проверки.
# db_schema. Совпадает с дефолтом, поэтому init пишет его закомментированным; задаём
# явно, чтобы файл сам говорил, где лежат данные.
python3 - "$INI" "$PORT" "$CONTROL_PORT" "$DB_CONNECTION" "$DB_SCHEMA" <<'PY'
import re, secrets, sys

ini, port, control_port, db_connection, db_schema = sys.argv[1:6]
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


s = set_key(s, "port", port, "TRANSPORT")
s = set_key(s, "control_port", control_port, "TRANSPORT")
s = set_key(s, "log_tls_errors", "off", "TRANSPORT")
s = set_key(s, "control_port_admin_password", secrets.token_hex(16), "AUTH")
s = set_key(s, "control_port_user_password", secrets.token_hex(16), "AUTH")
s = set_key(s, "db_connection", db_connection, "STORE_LOG")
s = set_key(s, "db_schema", db_schema, "STORE_LOG")
s = set_key(s, "log_stats", "off", "STORE_LOG")
s = set_key(s, "prometheus_interval", "60", "STORE_LOG")
s = set_key(s, "disconnect", "off", "INACTIVE_CLIENTS")

with open(ini, "w", encoding="utf-8") as fh:
    fh.write(s)
print("ini: port=%s control_port=%s, пароли control port заданы" % (port, control_port))
PY

# Адрес собираем сами: init печатает его с портом по умолчанию (443), а не с нашим.
FINGERPRINT="$(tr -d '[:space:]' < "$CONFIG_DIR/fingerprint")"
ADDRESS="ntf://$FINGERPRINT@$NODE_HOST:$PORT"
printf '%s\n' "$ADDRESS" > "$CONFIG_DIR/address"

chown -R "$NTF_USER:$NTF_USER" "$CONFIG_DIR" "$LOG_DIR"
# Группе — чтение: hearthd состоит в simplex-ntf и архивирует этот каталог. Без CA в
# архиве перенос узла сменил бы адрес, вшитый в сборки.
chmod -R g+rX "$CONFIG_DIR"
# В ini — пароли control port. Группе их читать незачем.
chmod 0600 "$INI"

echo "== 3. что нужно службе, но init не создаёт"
missing=()
[[ -f "$APNS_KEY" ]] || missing+=("$APNS_KEY — ключ APNs, 0600 root:root (runbook-ntf.md, шаг 4)")
[[ -f "$NTF_ENV" ]]  || missing+=("$NTF_ENV — APNS_KEY_ID, APNS_TEAM_ID, APNS_TOPIC (шаг 4)")
if [[ ! -f "$NTF_RESOLV" ]]; then
    if [[ -n "${ROUTER_DNS:-}" ]]; then
        printf '# hearth: резолвер только для ntf-server (ADR 0016); остальной узел не резолвит\nnameserver %s\n' \
            "$ROUTER_DNS" > "$NTF_RESOLV"
        chmod 0644 "$NTF_RESOLV"
        echo "   $NTF_RESOLV -> $ROUTER_DNS"
    else
        missing+=("$NTF_RESOLV — резолвер для службы (ROUTER_DNS=<адрес роутера> создаст его здесь)")
    fi
fi
if [[ ${#missing[@]} -eq 0 ]]; then
    echo "   всё на месте"
else
    for item in "${missing[@]}"; do
        echo "   !! нет $item"
    done
fi

cat <<NEXT

OK. Адрес push-сервера (он же в $CONFIG_DIR/address):

  $ADDRESS

Этот адрес ВШИВАЕТСЯ в сборку iOS-приложения. Секрета в нём нет, но смена отпечатка
ломает пуши у всех установленных сборок — поэтому ключи CA переезжают вместе с узлом.

Дальше:
  1. ./verify-ini-keys.sh $INI ntf/ntf-server.ini.example
     Особое внимание: port = $PORT (НЕ 443) и control_port = $CONTROL_PORT.
  2. hearthd.toml: [ntf] enabled = true, ntf-server в egress.relay_processes и
     [[egress.process_allow]] для Apple (docs/runbook-ntf.md, шаг 6).
  3. Проброс $PORT/tcp на роутере, затем
     systemctl enable --now ntf-server ntf-db-dump.timer && hearthctl health
  4. ca.key в $CONFIG_DIR нужен только для перевыпуска онлайн-сертификата
     (ntf-server cert). Upstream советует хранить его офлайн; решение — как для smp.
NEXT
