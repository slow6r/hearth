#!/usr/bin/env bash
# Инициализация SMP-релея. Запускается ОДИН РАЗ за жизнь узла.
#
# Создаёт CA релея, ключи и fingerprint в /etc/opt/simplex. Отпечаток этого CA входит
# в адрес smp://<fp>:<pass>@<host>:5223 — повторный init означает новый адрес и ручную
# перенастройку всех контактов у всех членов семьи. Скрипт на это молча не согласится.
#
# Флаги сверены с simplexmq v7.0.1 (`smp-server init --help` пинованного бинаря):
# --ip, --fqdn, --password, --control-port, --source-code, --disable-web.
set -euo pipefail

# Публичное имя или адрес, под которым узел известен клиентам.
NODE_HOST="${NODE_HOST:?укажите NODE_HOST=<домен или публичный IP> — то же значение, что node.host в hearthd.toml}"
SECRETS_DIR="${SECRETS_DIR:-/etc/hearth/secrets}"
PASSWORD_FILE="$SECRETS_DIR/smp-create-password"
CONFIG_DIR="${CONFIG_DIR:-/etc/opt/simplex}"
INI="$CONFIG_DIR/smp-server.ini"
SOURCE_CODE="${SOURCE_CODE:-https://github.com/simplex-chat/simplexmq}"

if [[ -f "$INI" ]]; then
    echo "!! $INI уже существует." >&2
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

# ЗАМЕЧАНИЕ. Пароль передаётся аргументом, то есть на время работы команды виден
# в /proc/<pid>/cmdline любому пользователю системы. Пинованная версия smp-server
# не умеет читать его из ENV или stdin (см. Server/Main.hs: только --password).
# Операция разовая и выполняется до того, как на машине появятся другие пользователи,
# но риск лучше знать, чем не знать.
#
# --source-code: обязательство AGPL. Без него сервер печатает при каждом старте
#   "Warning: server source code is not specified".
# --disable-web: статический мини-сайт upstream просит HTTPS-креды на node.host
#   (/etc/opt/simplex/web.crt|key) и без них печатает ошибку при КАЖДОМ старте.
#   Сертификата на node.host у нас нет; сам SMP на 443 при этом работает. Ссылка на
#   исходники доходит до клиента через [INFORMATION], а не через веб-страницу.
#   Флаг -l (store log) не передаётся: у v7.0.1 он DEPRECATED и включён по умолчанию.
#   NB: --source-code принимает значение ТОЛЬКО через `=`. Форма с пробелом
#   (`--source-code URI`) отвергается парсером как «Invalid argument».
smp-server init -y "${HOST_FLAG[@]}" --password "$PASSWORD" --control-port \
    "--source-code=$SOURCE_CODE" --disable-web

# --- то, что init оставляет в дефолте, а конфигурация требует иначе ---------------
python3 - "$INI" "$NODE_HOST" <<'PY'
import re, sys

ini, node_host = sys.argv[1], sys.argv[2]
with open(ini, encoding="utf-8") as fh:
    s = fh.read()


def set_key(text, key, value, section_hint=None):
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


# Метрики для node_exporter (textfile-коллектор), см. deploy/monitoring/README.md.
s = set_key(s, "prometheus_interval", "60", "STORE_LOG")
# Суточная статистика в CSV — это метаданные. Не нужна.
s = set_key(s, "log_stats", "off", "STORE_LOG")
# В TLS-ошибки попадают адреса клиентов.
s = set_key(s, "log_tls_errors", "off", "TRANSPORT")
# Телефон в энергосбережении молчит часами. Дефолт upstream (disconnect = on,
# ttl = 21600) отключал бы его каждые шесть часов; на 20 устройств экономить сокеты
# незачем, а переподключения стоят батареи.
s = set_key(s, "disconnect", "off", "INACTIVE_CLIENTS")
# Свои домены — для отдельной статистики прокси. Для голого IP смысла нет.
if not re.match(r"^\d+\.\d+\.\d+\.\d+$", node_host):
    s = set_key(s, "own_server_domains", node_host, "PROXY")
# init сам вписывает `hosting_type = virtual`. Это утверждение о факте, которое
# сервер печатает клиентам, и оно неверно: узел — железо дома, а не VPS.
# [INFORMATION] должна остаться минимальной (ТЗ §6.2), поэтому просто убираем.
s = re.sub(r"(?m)^hosting_type\s*=.*$", "# hosting_type =", s, count=1)

with open(ini, "w", encoding="utf-8") as fh:
    fh.write(s)
print("ini: prometheus_interval=60, log_stats=off, disconnect=off")
PY

umask 077
printf '%s\n' "$PASSWORD" > "$PASSWORD_FILE"
# hearthd работает от пользователя hearth и обязан прочитать этот пароль, чтобы
# собрать адрес релея для bundle. root:root 0600 сломал бы выпуск bundle с EACCES.
chown root:hearth "$PASSWORD_FILE" 2>/dev/null || true
chmod 0640 "$PASSWORD_FILE"
unset PASSWORD

# Каталоги релея создаёт root — отдать их пользователю релея и открыть чтение
# группе, иначе не заработают ни bundle (нужен fingerprint), ни ночной бэкап.
chown -R simplex:simplex "$CONFIG_DIR" 2>/dev/null || true
chmod -R g+rX "$CONFIG_DIR" 2>/dev/null || true
# В ini лежат create_password и пароли control port — группе их читать незачем.
chmod 0600 "$INI" 2>/dev/null || true
chown simplex:simplex "$INI" 2>/dev/null || true

cat <<NEXT

OK. Дальше:
  1. Привести $INI к целевой конфигурации:
     ./verify-ini-keys.sh $INI smp/smp-server.ini.example
     Особое внимание: port = 5223,443 и пароли control port.
  2. Пароль на создание очередей — в $PASSWORD_FILE (0640 root:hearth). Оттуда его
     читает hearthd. На публично доступном релее это единственное, что отделяет
     посторонних от создания очередей — не потеряйте и не публикуйте.
  3. Отпечаток CA: $CONFIG_DIR/fingerprint — это часть адреса релея.
  4. systemctl enable --now smp-server && hearthctl health
NEXT
