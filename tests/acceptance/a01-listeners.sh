#!/usr/bin/env bash
# A1 — что слушает узел.
#
# Модель изменилась (ADR 0007): релеи слушают все интерфейсы и это НОРМАЛЬНО —
# upstream документирует `[TRANSPORT] host` как «only used to print server address on
# start». Поэтому проверяем не «нет 0.0.0.0», а то, что действительно важно:
#
#   * релейные порты слушаются;
#   * control-порты — только на loopback;
#   * admin API — только на LAN-адресе, никогда не на wildcard.
#
# Device API и push-сервер (ADR 0016) есть не на каждом узле: их порты проверяются,
# только если соответствующая секция включена в hearthd.toml.
set -uo pipefail

CONFIG="${CONFIG:-/etc/hearth/hearthd.toml}"
API_PORT="${API_PORT:-7443}"
# 8443 — порт в адресах клиентов (провайдер узла режет 443 и 5223, см.
# docs/deploy-fels-2026-09-09.md); старые 443 и 5223 релей слушает по-прежнему.
RELAY_PORTS="${RELAY_PORTS:-8443 5223 443 5443}"
CONTROL_PORTS="${CONTROL_PORTS:-5224 5444}"

command -v ss >/dev/null || { echo "нет ss — пропуск"; exit 77; }

# Значение ключа из секции hearthd.toml. Разбор нарочно примитивный: полноценный
# парсер тесту не нужен. Понимает `key = value`, кавычки и комментарий в конце строки.
toml_value() {
    local section="$1" key="$2"
    [[ -r "$CONFIG" ]] || return 0
    awk -v section="[$section]" -v key="$key" '
        {
            line = $0
            sub(/[[:space:]]*#.*$/, "", line)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
        }
        line ~ /^\[/ { in_section = (line == section); next }
        in_section && line ~ ("^" key "[[:space:]]*=") {
            sub("^" key "[[:space:]]*=[[:space:]]*", "", line)
            gsub(/"/, "", line)
            print line
            exit
        }
    ' "$CONFIG"
}

if [[ "$(toml_value device_api enabled)" == "true" ]]; then
    device_listen="$(toml_value device_api listen)"
    device_port="${device_listen##*:}"
    RELAY_PORTS="$RELAY_PORTS ${device_port:-7444}"
fi
if [[ "$(toml_value ntf enabled)" == "true" ]]; then
    ntf_port="$(toml_value ntf port)"
    ntf_control="$(toml_value ntf control)"
    RELAY_PORTS="$RELAY_PORTS ${ntf_port:-2053}"
    [[ -n "$ntf_control" ]] && CONTROL_PORTS="$CONTROL_PORTS ${ntf_control##*:}"
fi

LISTENERS="$(ss -tlnH 2>/dev/null)"
echo "Слушающие TCP-сокеты:"
echo "$LISTENERS" | sed 's/^/  /'
echo

status=0

# МАСКА ПОРТА. Раньше здесь стояло `(^|[^0-9]):$port` — требование, чтобы перед
# двоеточием был не-цифра. Для сокета, привязанного к конкретному адресу, перед
# двоеточием стоит последняя цифра октета, поэтому маска не срабатывала НИКОГДА:
#
#   *:443            -> перед двоеточием `*`, совпадало
#   0.0.0.0:7444     -> перед двоеточием `0`, не совпадало
#   127.0.0.1:5224   -> перед двоеточием `1`, не совпадало
#
# Поэтому проверки 2 и 3 ниже всегда уходили в ветку «не слушается» и печатали `?`:
# тест, который обязан поймать control-порт, вынесенный с loopback наружу, не мог
# сработать в принципе. Ограждение и не нужно — `:443` не встречается внутри `:8443`,
# там после двоеточия идёт `8`, а `` не даёт совпасть с `:4430`.
# 1. Публичные порты должны слушаться (на любом адресе — это ожидаемо).
for port in $RELAY_PORTS; do
    if grep -qE ":$port\b" <<<"$LISTENERS"; then
        echo "  ok   слушается :$port"
    else
        echo "  !!   никто не слушает :$port"
        status=1
    fi
done

# 2. Control-порты — строго loopback. Через них управляют релеем.
for port in $CONTROL_PORTS; do
    lines="$(grep -E ":$port\b" <<<"$LISTENERS" || true)"
    if [[ -z "$lines" ]]; then
        echo "  ?    control port :$port не слушается (релей выключен?)"
        continue
    fi
    if grep -qvE "127\.0\.0\.1:$port|\[::1\]:$port" <<<"$lines"; then
        echo "  !!   control port :$port слушает НЕ на loopback:"
        sed 's/^/       /' <<<"$lines"
        status=1
    else
        echo "  ok   control port :$port только на loopback"
    fi
done

# 3. Admin API не должен быть на wildcard — это единственный «наш» сервис,
#    и он не для интернета.
api_lines="$(grep -E ":$API_PORT\b" <<<"$LISTENERS" || true)"
if [[ -z "$api_lines" ]]; then
    echo "  ?    admin API :$API_PORT не слушается (hearthd не запущен?)"
elif grep -qE "0\.0\.0\.0:$API_PORT|\[::\]:$API_PORT|\*:$API_PORT" <<<"$api_lines"; then
    echo "  !!   admin API слушает wildcard — он должен быть привязан к LAN-адресу"
    sed 's/^/       /' <<<"$api_lines"
    status=1
else
    echo "  ok   admin API привязан к конкретному адресу"
fi

echo
echo "  Снаружи это проверяется тестом A4 (скан с другой машины)."
exit $status
