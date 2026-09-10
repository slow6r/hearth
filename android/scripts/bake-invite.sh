#!/usr/bin/env bash
# Вшить приглашение в сборку (ADR 0011).
#
# Приглашение — то, что делает первый запуск похожим на SimpleX: человек ставит
# приложение и сразу им пользуется, потому что телефон заводит себя сам. В сборке
# лежит адрес узла и одноразовый токен, паролей релеев там НЕТ.
#
# Пока приглашение живо, файл APK впускает в контур. Поэтому:
#   * срок и число использований задаются при выписке (`hearthctl invite create`);
#   * раздали — гасите: `hearthctl invite revoke <id>`;
#   * файл с токеном стирается сразу после сборки, а не «когда-нибудь».
#
# Использование:
#   hearthctl invite create --uses 20 --days 7 --write-token /dev/shm/invite.token
#   ./bake-invite.sh relay.myhearth.ru 7444 /dev/shm/invite.token
#   ./build-release.sh
#   ./bake-invite.sh --remove
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/simplex-chat}"
RES="$FORK/apps/multiplatform/android/src/main/res/raw/hearth_invite.json"

# Файл с секретом не должен попасть в историю форка ни при каких обстоятельствах.
# .gitignore трогать нельзя — это файл upstream, и правка в нём означала бы конфликт
# при каждом ребейзе. info/exclude делает то же самое и живёт только локально.
exclude_path() {
    local ex="$FORK/.git/info/exclude"
    [ -d "$FORK/.git" ] || return 0
    local line="apps/multiplatform/android/src/main/res/raw/hearth_invite.json"
    grep -qxF "$line" "$ex" 2>/dev/null || echo "$line" >> "$ex"
}

if [ "${1:-}" = "--remove" ]; then
    if [ -f "$RES" ]; then
        shred -u "$RES" 2>/dev/null || rm -f "$RES"
        echo "приглашение убрано из дерева сборки"
    else
        echo "приглашения в дереве сборки нет"
    fi
    exit 0
fi

HOST="${1:?нужен хост узла, например relay.myhearth.ru}"
PORT="${2:?нужен порт device API, например 7444}"
TOKEN_FILE="${3:?нужен файл с токеном (hearthctl invite create --write-token)}"

[ -f "$TOKEN_FILE" ] || { echo "нет файла с токеном: $TOKEN_FILE" >&2; exit 1; }
TOKEN="$(tr -d ' \t\r\n' < "$TOKEN_FILE")"
# Проверяем здесь, а не в приложении: сборка с битым токеном молча показала бы людям
# сканер, и разбираться пришлось бы по звонку «а почему тут камера».
[[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || { echo "токен должен быть 64 hex-символами" >&2; exit 1; }
[[ "$HOST" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || { echo "хост, а не URL: $HOST" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || { echo "порт числом: $PORT" >&2; exit 1; }

exclude_path
mkdir -p "$(dirname "$RES")"
umask 077
printf '{"host":"%s","port":%s,"token":"%s"}\n' "$HOST" "$PORT" "$TOKEN" > "$RES"
chmod 600 "$RES"

echo "приглашение вшито: $HOST:$PORT"
echo
echo "Дальше:"
echo "  1. ./build-release.sh   — собрать"
echo "  2. подписать тем же ключом, иначе обновление поверх не встанет"
echo "  3. ./bake-invite.sh --remove   — убрать токен из дерева сборки"
echo "  4. когда раздали — hearthctl invite revoke <id>"
echo
echo "Сборка с приглашением НЕ кладётся в updates_dir: обновление получают уже"
echo "заведённые устройства, и второй раз заводиться им незачем."
