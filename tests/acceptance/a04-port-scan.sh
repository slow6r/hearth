#!/usr/bin/env bash
# A4 — снаружи открыты только нужные порты (ТЗ §5.3, §12).
#
# Запускать С ДРУГОЙ МАШИНЫ в WG, а не с самого узла: с узла всё выглядит открытым,
# потому что iif lo accept.
#
#   TARGET=10.66.10.10 ./a04-port-scan.sh
set -uo pipefail

TARGET="${TARGET:-10.66.10.10}"

if [[ -e /etc/hearth/hearthd.toml && "${FORCE:-0}" != "1" ]]; then
    echo "Похоже, это сам узел. Тест надо запускать с другой машины в WG."
    echo "FORCE=1 чтобы всё равно выполнить."
    exit 77
fi
command -v nmap >/dev/null || { echo "нет nmap — пропуск"; exit 77; }

echo "Сканирование $TARGET (это займёт минуту)..."
OPEN="$(nmap -Pn -p- --open -T4 "$TARGET" 2>/dev/null | grep -E '^[0-9]+/tcp' | cut -d/ -f1)"
UDP="$(nmap -Pn -sU -p 3478 --open "$TARGET" 2>/dev/null | grep -cE '^3478/udp.*open' || true)"

echo "Открытые TCP-порты:"
echo "${OPEN:-  (нет)}" | sed 's/^/  /'

status=0
ALLOWED_FROM_CLIENTS="5223 5443"
ADMIN_ONLY="7443 22"

for port in $OPEN; do
    if grep -qw "$port" <<<"$ALLOWED_FROM_CLIENTS"; then
        echo "  ok $port — релей, доступен из WG по замыслу"
    elif grep -qw "$port" <<<"$ADMIN_ONLY"; then
        echo "  ?  $port — админский порт. Если вы сканируете ИЗ админ-подсети (10.66.0.0/24),"
        echo "     это норма. Если из клиентской (10.66.100.x) — это нарушение ТЗ §5.3."
    else
        echo "  !! $port — лишний открытый порт"
        status=1
    fi
done

if [[ "$UDP" -gt 0 ]]; then
    echo "  ok 3478/udp — STUN/TURN"
else
    echo "  ?  3478/udp закрыт или не определился (UDP-скан ненадёжен без root)"
fi

for port in 5223 5443; do
    grep -qw "$port" <<<"$OPEN" || { echo "  !! $port закрыт — релей недоступен клиентам"; status=1; }
done

exit $status
