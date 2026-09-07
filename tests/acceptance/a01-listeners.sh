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
set -uo pipefail

API_PORT="${API_PORT:-7443}"
RELAY_PORTS="${RELAY_PORTS:-5223 443 5443}"
CONTROL_PORTS="${CONTROL_PORTS:-5224 5444}"

command -v ss >/dev/null || { echo "нет ss — пропуск"; exit 77; }

LISTENERS="$(ss -tlnH 2>/dev/null)"
echo "Слушающие TCP-сокеты:"
echo "$LISTENERS" | sed 's/^/  /'
echo

status=0

# 1. Релейные порты должны слушаться (на любом адресе — это ожидаемо).
for port in $RELAY_PORTS; do
    if grep -qE "(^|[^0-9]):$port\b" <<<"$LISTENERS"; then
        echo "  ok   релей слушает :$port"
    else
        echo "  !!   никто не слушает :$port"
        status=1
    fi
done

# 2. Control-порты — строго loopback. Через них управляют релеем.
for port in $CONTROL_PORTS; do
    lines="$(grep -E "(^|[^0-9]):$port\b" <<<"$LISTENERS" || true)"
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
api_lines="$(grep -E "(^|[^0-9]):$API_PORT\b" <<<"$LISTENERS" || true)"
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
