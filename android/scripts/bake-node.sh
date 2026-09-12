#!/usr/bin/env bash
# Вшить адрес узла в сборку (ADR 0011, ADR 0012).
#
# # Что изменилось и почему
#
# Раньше сюда клали токен приглашения, и файл APK сам по себе впускал в контур: кто
# его достал, тот и завёлся. Это был осознанный размен ради «поставил и пользуйся»,
# и он же был самым слабым местом раздачи.
#
# Теперь входной секрет приносит человек — код доступа, выданный лично
# (`hearthctl invite create --count N --uses 1 --write-codes …`). В сборке остаётся
# только адрес узла, а это не тайна: его видно в любом соединении с релеем.
#
# Отсюда следствия, которые стоят того, чтобы их назвать:
#   * APK можно передавать как угодно — без кода он ничего не открывает;
#   * ничего не надо стирать после сборки: стирать нечего;
#   * отзывают не сборку, а код: `hearthctl invite revoke <id>`.
#
# Использование:
#   ./bake-node.sh relay.myhearth.ru 7444
#   ./build-release.sh
#   ./bake-node.sh --remove     # если нужна сборка без вшитого адреса (настройка по QR)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FORK="${FORK_DIR:-$HERE/simplex-chat}"
ANDROID_RES="$FORK/apps/multiplatform/android/src/main/res/raw/hearth_node.json"
DESKTOP_RES="$FORK/apps/multiplatform/common/src/desktopMain/resources/hearth_node.json"
ANDROID_CA="$FORK/apps/multiplatform/android/src/main/res/raw/hearth_ca.pem"
RELEASE_PUB="$HERE/../keys/admin/release-sign.pub"
ANDROID_RELEASE_KEY="$FORK/apps/multiplatform/android/src/main/res/raw/hearth_release_key.pub"
DESKTOP_CA="$FORK/apps/multiplatform/common/src/desktopMain/resources/hearth_ca.pem"

if [ "${1:-}" = "--remove" ]; then
    removed=0
    for res in "$ANDROID_RES" "$DESKTOP_RES" "$DESKTOP_CA" "$ANDROID_RELEASE_KEY"; do
        if [ -f "$res" ]; then rm -f "$res"; removed=$((removed + 1)); fi
    done
    echo "адрес узла убран из дерева сборки (файлов: $removed)"
    exit 0
fi

HOST="${1:?нужен хост узла, например relay.myhearth.ru}"
PORT="${2:?нужен порт device API, например 7444}"

# Проверяем здесь, а не в приложении: сборка с битым адресом молча показала бы людям
# сканер QR, и разбираться пришлось бы по звонку «а почему тут камера».
[[ "$HOST" =~ ^[A-Za-z0-9.-]{1,253}$ ]] || { echo "хост, а не URL: $HOST" >&2; exit 1; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || { echo "порт числом: $PORT" >&2; exit 1; }

for res in "$ANDROID_RES" "$DESKTOP_RES"; do
    mkdir -p "$(dirname "$res")"
    printf '{"host":"%s","port":%s}\n' "$HOST" "$PORT" > "$res"
done

# Сертификат узла настольной сборке нужен отдельно. На Android его подставляет
# платформа через network security config, а на JVM такого механизма нет: узел
# подписан своим CA, и без этого файла соединение упало бы на проверке цепочки.
# Это не секрет — корневой сертификат, его видно в каждом рукопожатии.
# Открытый ключ подписи манифестов обновления. Не секрет: секретна закрытая
# половина, и она остаётся на рабочей станции. Без этого файла сборка не умеет
# проверить, что манифест выпустили мы, — и захваченный узел смог бы подсунуть свой.
if [ -f "$RELEASE_PUB" ]; then
    cp "$RELEASE_PUB" "$ANDROID_RELEASE_KEY"
    echo "ключ подписи манифестов вшит"
else
    echo "ВНИМАНИЕ: нет $RELEASE_PUB — сборка не сможет проверить подпись манифеста" >&2
    echo "          выпустите: hearthctl release keygen --out keys/admin" >&2
fi

if [ -f "$ANDROID_CA" ]; then
    cp "$ANDROID_CA" "$DESKTOP_CA"
    echo "сертификат узла скопирован в ресурсы desktop"
else
    echo "ВНИМАНИЕ: нет $ANDROID_CA — настольная сборка не сможет довериться узлу" >&2
fi

echo "адрес узла вшит: $HOST:$PORT"
echo "  android: $ANDROID_RES"
echo "  desktop: $DESKTOP_RES"
echo
echo "Дальше:"
echo "  1. ./build-release.sh — собрать (и desktop-пакет, если нужен MSI)"
echo "  2. подписать тем же ключом, иначе обновление поверх не встанет"
echo "  3. раздать коды доступа: hearthctl invite create --count N --uses 1 --write-codes <файл>"
echo
echo "Секрета в сборке нет: без кода доступа приложение ничего не открывает."
