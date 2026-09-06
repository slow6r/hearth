#!/usr/bin/env bash
# A1 — релеи слушают только 10.66.10.10 и 127.0.0.1, никаких 0.0.0.0 (ТЗ §5.1, §12).
set -uo pipefail

NODE_IP="${NODE_IP:-10.66.10.10}"
command -v ss >/dev/null || { echo "нет ss — пропуск"; exit 77; }

echo "Слушающие TCP-сокеты:"
LISTENERS="$(ss -tlnH 2>/dev/null)"
echo "$LISTENERS" | sed 's/^/  /'

status=0
while read -r _ _ _ local _; do
    [[ -z "${local:-}" ]] && continue
    host="${local%:*}"
    host="${host#[}"; host="${host%]}"
    case "$host" in
        "$NODE_IP"|127.0.0.1|::1) ;;
        0.0.0.0|"*"|"::")
            echo "  !! wildcard-бинд: $local"
            status=1
            ;;
        *)
            echo "  ?  посторонний адрес: $local (проверьте, что это не релей)"
            ;;
    esac
done <<<"$LISTENERS"

# Порты, которые ОБЯЗАНЫ слушать на адресе узла
for port in 5223 5443 7443; do
    if grep -q "$NODE_IP:$port" <<<"$LISTENERS"; then
        echo "  ok $NODE_IP:$port"
    else
        echo "  !! никто не слушает $NODE_IP:$port"
        status=1
    fi
done

# Control-порты — только loopback
for port in 5224 5444; do
    if grep -q "127.0.0.1:$port" <<<"$LISTENERS"; then
        echo "  ok 127.0.0.1:$port (control port)"
    elif grep -q ":$port" <<<"$LISTENERS"; then
        echo "  !! control port $port слушает не на loopback"
        status=1
    fi
done

exit $status
