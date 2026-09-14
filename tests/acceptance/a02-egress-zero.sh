#!/usr/bin/env bash
# A2 — счётчик egress_drop равен нулю (ТЗ §5.4, §12).
#
# Смысл теста: ноль означает, что ни один процесс на узле даже не пытался выйти наружу.
# Ненулевое значение — инцидент, а не шум.
set -uo pipefail

command -v nft >/dev/null || { echo "нет nft — пропуск"; exit 77; }

JSON="$(nft -j list counters table inet hearth 2>/dev/null)" || {
    echo "!! не удалось прочитать счётчики: ruleset hearth не загружен?"
    echo "   nft -f /etc/hearth/nftables/hearth.nft"
    exit 1
}

status=0
read_counter() {
    printf '%s' "$JSON" \
        | tr '{' '\n' \
        | grep "\"name\": \"$1\"" \
        | grep -o '"packets": [0-9]*' \
        | grep -o '[0-9]*' \
        | head -1
}

EGRESS="$(read_counter egress_drop)"
INPUT="$(read_counter input_drop)"
FORWARD="$(read_counter forward_drop)"
APP="$(read_counter app_egress)"
TURN="$(read_counter turn_egress)"
NTF="$(read_counter ntf_egress)"

if [[ -z "$EGRESS" ]]; then
    echo "!! счётчик egress_drop не найден. Правила используют анонимные счётчики?"
    echo "   Нужны именованные — см. docs/adr/0003-named-nft-counters.md"
    exit 1
fi

echo "  egress_drop  = $EGRESS  (ожидание: 0)"
echo "  input_drop   = ${INPUT:-?}   (на публичном узле растёт постоянно — это сканы интернета, норма)"
echo "  forward_drop = ${FORWARD:-?}   (ожидание: 0, узел не роутер)"

echo
echo "  Разрешённый egress (растёт — это норма, ADR 0008):"
echo "    app_egress   = ${APP:-нет счётчика}   (зал, обновления, ваши сервисы)"
echo "    turn_egress  = ${TURN:-нет счётчика}   (медиа звонков)"
echo "    ntf_egress   = ${NTF:-нет счётчика}   (пуши в Apple, 17.0.0.0/8:443 — только с [ntf], ADR 0016)"
echo

if [[ "$EGRESS" -ne 0 ]]; then
    echo "!! РЕЛЕЙНЫЙ СТЕК ПЫТАЛСЯ ВЫЙТИ НАРУЖУ. Это инцидент."
    echo "   hearthctl egress --incidents"
    echo "   journalctl -k | grep hearth-egress-drop | tail -20"
    status=1
fi
if [[ -n "$FORWARD" && "$FORWARD" -ne 0 ]]; then
    echo "!! forward_drop не ноль: кто-то пытается маршрутизировать через узел"
    status=1
fi

if command -v hearthctl >/dev/null; then
    echo
    echo "  Проверка сокетов (вторая половина детектора):"
    hearthctl egress 2>/dev/null | sed 's/^/  /' || echo "  (hearthctl недоступен — нужен сертификат админа)"
fi

exit $status
