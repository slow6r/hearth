#!/usr/bin/env bash
# Вшить в сборку iOS адрес узла, его корневой сертификат и адрес push-сервера.
#
#   ios/scripts/bake-node.sh relay.myhearth.ru 7444 'ntf://<fp>@relay.myhearth.ru:<port>' [ca.pem]
#   ios/scripts/bake-node.sh relay.myhearth.ru 7444 --no-ntf [ca.pem]
#   ios/scripts/bake-node.sh --remove
#
# --no-ntf — узел без push-сервера: ключ "ntf" в hearth_node.json не пишется вовсе.
# Ядро получает пустой HEARTH_NTF_SERVERS, а это по патчу 0101 значит «push-серверов
# нет», а не «возьми серверы SimpleX» (HearthCoreEnvironment.prepare). Уведомлений в
# такой сборке не будет. Выдуманный адрес вместо --no-ntf ставить нельзя: он пройдёт
# проверку формата, уедет в ядро и превратится в стук в несуществующую дверь.
#
# Секретов здесь нет (ADR 0012): хост и порт device API, публичный CA и адрес
# ntf-server — у push-сервера пароля нет. Адрес ntf печатает relays/ntf/init-ntf.sh.
#
# Почему адрес push-сервера вшивается, а не приходит с bundle: ядро читает его один раз
# при старте процесса (ios/patches/0101), а первый старт случается раньше, чем узел
# выдаст bundle. Приехавший с bundle адрес заработал бы только после перезапуска.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/../android/simplex-chat}"
RES="$FORK/apps/ios/SimpleXChat/Hearth/Resources"
NODE_JSON="$RES/hearth_node.json"
CA_DST="$RES/hearth_ca.pem"

if [ "${1:-}" = "--remove" ]; then
    rm -f "$NODE_JSON" "$CA_DST"
    echo "убрано: $NODE_JSON, $CA_DST"
    exit 0
fi

HOST="${1:?usage: bake-node.sh <host> <port> <ntf-address> [ca.pem]}"
PORT="${2:?port}"
NTF="${3:?ntf address (ntf://<fp>@$HOST:<port>) либо --no-ntf}"
# По умолчанию — тот же CA, что уже вшит в Android-сборку: узел один.
CA_SRC="${4:-$FORK/apps/multiplatform/android/src/main/res/raw/hearth_ca.pem}"

[[ "$HOST" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || { echo "плохой хост: $HOST" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] \
    || { echo "плохой порт: $PORT" >&2; exit 1; }
# ntf://<fingerprint>@<тот же хост>:<порт> — без пароля. Хост обязан совпасть: push-сервер
# на чужом адресе — ровно та утечка, ради которой правили ядро.
if [ "$NTF" != "--no-ntf" ]; then
    NTF_RE="^ntf://[A-Za-z0-9_=-]+@([A-Za-z0-9.-]+):([0-9]{1,5})$"
    [[ "$NTF" =~ $NTF_RE ]] || { echo "плохой адрес ntf: $NTF" >&2; exit 1; }
    NTF_HOST_LC="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    HOST_LC="$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')"
    [ "$NTF_HOST_LC" = "$HOST_LC" ] || { echo "ntf на другом хосте (${BASH_REMATCH[1]} ≠ $HOST)" >&2; exit 1; }
fi
[ -f "$CA_SRC" ] || { echo "нет CA: $CA_SRC — возьмите /etc/hearth/pki/ca.pem с узла" >&2; exit 1; }
grep -q -- '-----BEGIN CERTIFICATE-----' "$CA_SRC" || { echo "$CA_SRC — не PEM-сертификат" >&2; exit 1; }
if grep -q -- 'PRIVATE KEY' "$CA_SRC"; then
    echo "$CA_SRC содержит закрытый ключ — такой файл в сборку не кладём" >&2
    exit 1
fi

mkdir -p "$RES"
if [ "$NTF" = "--no-ntf" ]; then
    printf '{"host":"%s","port":%s}\n' "$HOST" "$PORT" > "$NODE_JSON"
    echo "!! БЕЗ PUSH-СЕРВЕРА: уведомлений в этой сборке не будет." >&2
    echo "   Когда на узле отработает relays/ntf/init-ntf.sh, перевшить настоящий адрес" >&2
    echo "   и выпустить новую сборку — вшитый адрес иначе не меняется." >&2
else
    printf '{"host":"%s","port":%s,"ntf":"%s"}\n' "$HOST" "$PORT" "$NTF" > "$NODE_JSON"
fi
cp "$CA_SRC" "$CA_DST"
echo "вшито: $NODE_JSON"
cat "$NODE_JSON"
echo "CA: $(openssl x509 -in "$CA_DST" -noout -subject -fingerprint -sha256 2>/dev/null || echo "$CA_DST")"
echo
echo "Дальше: ios/scripts/sync-overlay.sh — ресурсы должны попасть в project.pbxproj."
