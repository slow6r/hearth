#!/usr/bin/env bash
# A4 — что видно снаружи.
#
# Запускать НЕ с узла и НЕ из домашней сети: нужен взгляд из интернета. Идеально —
# с телефона по мобильному интернету (termux) или с любого VPS.
#
#   TARGET=relay.example.org ./a04-port-scan.sh
#   TARGET=relay.example.org NTF_PORT=2053 ./a04-port-scan.sh   # узел с push-сервером
#
# Ожидание:
#   открыты   8443, 5223, 443, 5443, 7444 (tcp), 3478 (udp/tcp), 49160-49200 (udp)
#             + порт push-сервера (tcp), если он заведён (ADR 0016)
#   закрыты   7443 (admin API), 22 (ssh) — они только для LAN
set -uo pipefail

# Порядок важен: «я на узле» проверяется ДО требования TARGET. Иначе `run-all.sh` на
# самом узле падает на отсутствующей переменной и рисует FAIL там, где по смыслу SKIP —
# а красный тест, который «всегда красный и это нормально», перестают читать.
if [[ -e /etc/hearth/hearthd.toml && "${FORCE:-0}" != "1" ]]; then
    echo "Это сам узел. Тест надо запускать снаружи — иначе он ничего не докажет."
    echo "  TARGET=<node.host> ./a04-port-scan.sh      # с VPS или телефона по мобильной сети"
    echo "FORCE=1 чтобы всё равно выполнить здесь."
    exit 77
fi

TARGET="${TARGET:?укажите TARGET=<node.host>}"
command -v nmap >/dev/null || { echo "нет nmap — пропуск"; exit 77; }

# Снаружи конфига узла не видно, поэтому набор портов задаётся здесь. По умолчанию —
# то, что публикует развёрнутый узел: 8443 в адресах клиентов, 443 и 5223 по-старому,
# 5443 XFTP, 3478 TURN, 7444 device API. Узел без device API: EXPECT_TCP без 7444.
EXPECT_TCP="${EXPECT_TCP:-8443 5223 443 5443 3478 7444}"
# Push-сервер есть не на каждом узле — его порт добавляется явно.
if [[ -n "${NTF_PORT:-}" ]]; then
    EXPECT_TCP="$EXPECT_TCP $NTF_PORT"
fi
read -r -a expected <<<"$EXPECT_TCP"
PORT_LIST="$(IFS=,; echo "${expected[*]}")"
PORT_RE="$(IFS='|'; echo "${expected[*]}")"

status=0

echo "== Порты, которые ДОЛЖНЫ быть открыты"
OPEN_TCP="$(nmap -Pn -p "$PORT_LIST" --open "$TARGET" 2>/dev/null \
            | grep -E '^[0-9]+/tcp' | cut -d/ -f1)"
# 3478/tcp тоже обязателен: TURN слушает и TCP, и через него проходят клиенты
# из сетей, где UDP зарезан.
for port in "${expected[@]}"; do
    if grep -qw "$port" <<<"$OPEN_TCP"; then
        echo "  ok   $port/tcp открыт"
    else
        echo "  !!   $port/tcp закрыт — клиенты не подключатся (проброс на роутере?)"
        status=1
    fi
done

echo
echo "== Порты, которые НЕ должны быть видны из интернета"
ADMIN_OPEN="$(nmap -Pn -p 7443,22 --open "$TARGET" 2>/dev/null \
              | grep -E '^[0-9]+/tcp' | cut -d/ -f1)"
for port in 7443 22; do
    if grep -qw "$port" <<<"$ADMIN_OPEN"; then
        echo "  !!   $port/tcp ОТКРЫТ НАРУЖУ — уберите проброс на роутере немедленно"
        status=1
    else
        echo "  ok   $port/tcp снаружи не виден"
    fi
done

echo
echo "== Ничего лишнего"
EXTRA="$(nmap -Pn -p- --open -T4 "$TARGET" 2>/dev/null \
         | grep -E '^[0-9]+/tcp' | cut -d/ -f1 \
         | grep -vE "^($PORT_RE)$" || true)"
if [[ -n "$EXTRA" ]]; then
    echo "  !!   лишние открытые порты:"
    sed 's/^/       /' <<<"$EXTRA"
    status=1
else
    echo "  ok   других открытых TCP-портов нет"
fi

echo
echo "== Звонки (UDP; nmap без root тут ненадёжен)"
if nmap -Pn -sU -p 3478 --open "$TARGET" 2>/dev/null | grep -qE '^3478/udp.*open'; then
    echo "  ok   3478/udp отвечает"
else
    echo "  ?    3478/udp не определился. Это часто ложная тревога для UDP-скана."
    echo "       Настоящая проверка — реальный звонок между двумя устройствами"
    echo "       в разных сетях (тест A8)."
fi
echo "  ?    диапазон 49160-49200/udp сканом не проверить осмысленно:"
echo "       порт открывается только на время конкретной TURN-аллокации."
echo "       Проверяется звонком (A8)."

exit $status
