#!/usr/bin/env bash
# Инициализация SMP-релея. Запускается ОДИН РАЗ за жизнь узла.
#
# Создаёт CA релея, ключи и fingerprint в /etc/opt/simplex. Отпечаток этого CA входит
# в адрес smp://<fp>:<pass>@<host>:5223 — повторный init означает новый адрес и ручную
# перенастройку всех контактов у всех членов семьи. Скрипт на это молча не согласится.
#
# Флаги сверены с simplexmq v7.0.1 (Server/Main.hs): --ip, --fqdn, --password,
# -l/--store-log, --control-port.
set -euo pipefail

# Публичное имя или адрес, под которым узел известен клиентам.
NODE_HOST="${NODE_HOST:?укажите NODE_HOST=<домен или публичный IP> — то же значение, что node.host в hearthd.toml}"
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
# Upstream допускает печатаемый ASCII без пробелов, '@', ':' и '/'. hex безопасен.
PASSWORD="$(openssl rand -hex 24)"

# --fqdn для доменного имени, --ip для голого адреса: сервер печатает его при старте
# и кладёт в сертификат.
if [[ "$NODE_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    HOST_FLAG=(--ip "$NODE_HOST")
else
    HOST_FLAG=(--fqdn "$NODE_HOST")
fi

smp-server init -y -l "${HOST_FLAG[@]}" --password "$PASSWORD" --control-port

umask 077
printf '%s\n' "$PASSWORD" > "$PASSWORD_FILE"
chmod 0600 "$PASSWORD_FILE"
unset PASSWORD

cat <<NEXT

OK. Дальше:
  1. Привести $CONFIG_DIR/smp-server.ini к целевой конфигурации:
     ./verify-ini-keys.sh $CONFIG_DIR/smp-server.ini smp/smp-server.ini.example
     Особое внимание: port = 5223,443 и пароли control port.
  2. Пароль на создание очередей — в $PASSWORD_FILE (0600). Оттуда его читает hearthd.
     На публично доступном релее это единственное, что отделяет посторонних от
     создания очередей — не потеряйте и не публикуйте.
  3. Отпечаток CA: $CONFIG_DIR/fingerprint — это часть адреса релея.
  4. systemctl enable --now smp-server && hearthctl health
NEXT
