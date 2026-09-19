#!/usr/bin/env bash
# Релизная сборка Android-клиента (ТЗ §8.4).
#
# Подпись здесь НЕ выполняется: ключ подписи офлайновый и hardware-backed (YubiKey/
# pkcs11), в CI его нет, подпись — отдельный ручной шаг на доверенной машине.
#
# ЧТО ПАСПОРТ ДОКАЗЫВАЕТ, А ЧТО НЕТ — назвать прямо, как в relays/ntf/build-ntf-server.sh.
#
#   доказывает:   из какого коммита форка и из какого коммита ЭТОГО репозитория
#                 (overlay, скрипты, вшитый адрес узла) собран APK; какие именно
#                 значения вшил bake-node.sh; каким инструментом собрано;
#   НЕ доказывает: воспроизводимость APK из Git. Нативное ядро libsimplex.so/
#                 libsupport.so мы не собираем — оно берётся из официального APK
#                 пинованного тега upstream (см. ниже). Значит полной цепочки
#                 «исходники → байты приложения» нет и не будет, пока ядро приходит
#                 чужой сборкой. Доверие к этой части держится на двух вещах: подписи
#                 APK нашим ключом и совпадении sha256 обеих .so с официальным
#                 артефактом пинованного тега. Это меньше, чем воспроизводимость, и
#                 говорить об этом надо честно, а не обходить.
#                 Gradle/AGP/JDK тоже не пиннятся по digest — версии печатаются в
#                 паспорт, но образа сборки нет.
set -euo pipefail

FORK_DIR="${FORK_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../simplex-chat" && pwd)}"

# Overlay раскладываем сами: файлы форка лежат в этом репозитории, и собирать до
# синхронизации — значит собрать сборку без части правок и не заметить этого.
bash "$(dirname "${BASH_SOURCE[0]}")/sync-overlay.sh"

# Дерево форка обязано быть чистым ПОСЛЕ раскладки overlay и вшивания адреса узла.
#
# Именно этого гейта не хватило при выпуске 7.0.1-h15: sync-overlay.sh разложил
# правки в рабочее дерево, сборка ушла людям, а в git форка исходников не было —
# указатель на коммит описывал предыдущую версию. Аудит нашёл это первым же
# вопросом «из чего собран APK», и ответить было нечем.
#
# Проверка намеренно стоит ПОСЛЕ sync-overlay: она требует, чтобы разложенное
# совпадало с закоммиченным, то есть чтобы overlay и форк не разъезжались.
if git -C "$FORK_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    DIRTY="$(git -C "$FORK_DIR" status --porcelain)"
    if [ -n "$DIRTY" ]; then
        echo "== дерево форка изменено после sync-overlay:" >&2
        printf '%s\n' "$DIRTY" >&2
        if [ "${HEARTH_ALLOW_DIRTY:-0}" = "1" ]; then
            echo "ВНИМАНИЕ: HEARTH_ALLOW_DIRTY=1 — собираю из изменённого дерева." >&2
            echo "Такую сборку НЕЛЬЗЯ раздавать: её нечем сопоставить с исходниками." >&2
        else
            echo >&2
            echo "Закоммитьте изменения в форке, затем перевыпустите патчи:" >&2
            echo "  git -C $FORK_DIR add -A apps/multiplatform && git -C $FORK_DIR commit" >&2
            echo "  android/scripts/export-fork-patches.sh" >&2
            echo "Для заведомо черновой сборки: HEARTH_ALLOW_DIRTY=1 ./build-release.sh" >&2
            exit 1
        fi
    fi
    FORK_COMMIT="$(git -C "$FORK_DIR" rev-parse HEAD)"
    echo "== Коммит форка: $FORK_COMMIT"
else
    echo "ВНИМАНИЕ: $FORK_DIR не git-репозиторий — сборку не с чем сопоставить." >&2
    FORK_COMMIT="unknown"
fi

# Патч 0004 (ICE): проверяем ИСХОДНИКИ, а не только готовый APK.
#
# verify-apk.sh смотрит в ассет собранного APK — и это правильная проверка, но она
# случается после сборки, когда время уже потрачено. Здесь то же самое по дереву
# форка, сразу после раскладки overlay: дешевле и раньше.
#
# Отдельная история — packages/simplex-chat-webrtc/src/call.ts, из которого call.js и
# ПОРОЖДАЕТСЯ. В нём публичные серверы upstream стоят до сих пор вместе с рабочими
# креденшелами: патч 0004 правил только результат сборки пакета, но не его источник.
# В APK это сегодня не попадает — webrtc-пакет мы не пересобираем, — поэтому здесь
# предупреждение, а не остановка: гейт, который валит каждую сборку из-за файла,
# которого в сборке нет, оставит семью без обновлений, а починить его этим скриптом
# нельзя (правка call.ts — патч к форку). Как только пакет пересоберут, вернувшиеся
# адреса поймает проверка call.js выше — уже жёстко.
CHECKS_LIB="$(dirname "${BASH_SOURCE[0]}")/lib/apk-checks.sh"
# shellcheck source=lib/apk-checks.sh
source "$CHECKS_LIB"
CALL_JS_PATH="$FORK_DIR/apps/multiplatform/common/src/commonMain/resources/assets/www/call.js"
if [ ! -f "$CALL_JS_PATH" ]; then
    echo "нет $CALL_JS_PATH — звонковый ассет пропал, собирать нечего" >&2
    exit 1
fi
CALL_JS="$(cat "$CALL_JS_PATH")"
for ice_check in check_no_public_ice check_ice_defaults_empty; do
    if out="$("$ice_check" "$CALL_JS" "assets/www/call.js")"; then
        echo "== $out"
    else
        echo "== ПАТЧ 0004 НАРУШЕН: $out" >&2
        exit 1
    fi
done
CALL_TS_PATH="$FORK_DIR/packages/simplex-chat-webrtc/src/call.ts"
if [ -f "$CALL_TS_PATH" ]; then
    if ! out="$(check_no_public_ice "$(cat "$CALL_TS_PATH")" "packages/simplex-chat-webrtc/src/call.ts")"; then
        echo "ВНИМАНИЕ: $out" >&2
        echo "  В APK это не попадает: call.js собран отдельно и проверен выше." >&2
        echo "  Но пересборка webrtc-пакета вернёт публичные серверы — патч 0004 надо" >&2
        echo "  распространить и на call.ts (см. android/patches/0004-ice-servers.md)." >&2
    fi
fi

# Коммит ЭТОГО репозитория. Половина изменений живёт здесь: overlay, скрипты,
# bake-node.sh. Гейт чистоты форка покрывает их лишь косвенно — он ловит расхождение
# разложенного с закоммиченным В ФОРКЕ, а правка overlay, не попавшая в git messanger,
# уедет в сборку и не оставит следа. Ровно этим способом и потерялся h15, только в
# другом дереве.
OVERLAY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if git -C "$OVERLAY_DIR" rev-parse --git-dir >/dev/null 2>&1; then
    OVERLAY_DIRTY="$(git -C "$OVERLAY_DIR" status --porcelain)"
    if [ -n "$OVERLAY_DIRTY" ]; then
        echo "== дерево overlay (messanger) изменено:" >&2
        printf '%s\n' "$OVERLAY_DIRTY" >&2
        if [ "${HEARTH_ALLOW_DIRTY:-0}" = "1" ]; then
            echo "ВНИМАНИЕ: HEARTH_ALLOW_DIRTY=1 — собираю из изменённого дерева." >&2
            echo "Такую сборку НЕЛЬЗЯ раздавать: её нечем сопоставить с исходниками." >&2
        else
            echo >&2
            echo "Закоммитьте изменения в messanger и повторите." >&2
            echo "Для заведомо черновой сборки: HEARTH_ALLOW_DIRTY=1 ./build-release.sh" >&2
            exit 1
        fi
    fi
    OVERLAY_COMMIT="$(git -C "$OVERLAY_DIR" rev-parse HEAD)"
    echo "== Коммит overlay (messanger): $OVERLAY_COMMIT"
else
    echo "ВНИМАНИЕ: $OVERLAY_DIR не git-репозиторий — overlay не с чем сопоставить." >&2
    OVERLAY_COMMIT="unknown"
fi

# Что вшил bake-node.sh. Именно эти три значения отличают нашу сборку от чистого
# upstream, и именно их не было в паспорте: APK с чужим адресом узла выглядел бы
# точно так же.
NODE_RES="$FORK_DIR/apps/multiplatform/android/src/main/res/raw/hearth_node.json"
NODE_CA="$FORK_DIR/apps/multiplatform/android/src/main/res/raw/hearth_ca.pem"
NODE_KEY="$FORK_DIR/apps/multiplatform/android/src/main/res/raw/hearth_release_key.pub"
baked() {
    if [ -f "$1" ]; then sha256sum "$1" | cut -d' ' -f1; else echo "absent"; fi
}
NODE_HOST_BAKED="absent"
if [ -f "$NODE_RES" ]; then
    # Адрес узла не тайна (его видно в любом соединении с релеем), поэтому пишем как есть.
    NODE_HOST_BAKED="$(tr -d ' \n' < "$NODE_RES")"
fi

cd "$FORK_DIR/apps/multiplatform"

# Нативное ядро на Haskell мы не собираем (android/README.md, раздел «Стратегия»):
# берём libsimplex.so и libsupport.so из официального APK пинованного тега и кладём
# туда же, куда их кладёт upstream'овский scripts/android/prepare.sh. Именно из APK,
# а не из сборки CI: так они гарантированно соответствуют тегу.
LIBS_DIR="common/src/commonMain/cpp/android/libs/arm64-v8a"
for lib in libsimplex.so libsupport.so; do
    [ -f "$LIBS_DIR/$lib" ] || { echo "нет $LIBS_DIR/$lib — см. android/README.md" >&2; exit 1; }
done
echo "== Нативное ядро (upstream, не наша сборка)"
sha256sum "$LIBS_DIR"/*.so

echo "== Версии инструментов (должны совпадать с gradle/libs.versions.toml)"
java -version 2>&1 | head -1
./gradlew --version | grep -E 'Gradle|JVM'

echo "== Сборка release (только arm64-v8a)"
# assembleFossRelease, а НЕ assembleRelease: upstream делает агрегирующие задачи
# (build, assemble, assembleRelease, bundle) падающими намеренно — они собрали бы
# релиз с Play Billing либо app bundle без него. Флейвор foss — это F-Droid и GitHub.
# Без -Pandroid.injected.build.abi: этот флаг означает «деплой из IDE на подключённое
# устройство», и AGP помечает такой APK как testOnly — Android отказывается ставить
# его обычным способом («приложение предназначено только для тестирования»).
# Ограничение ABI задано в android/build.gradle.kts, см. patches/0012.
./gradlew clean :android:assembleFossRelease --no-daemon

# Путь зависит от того, включены ли abi-splits: без них APK лежит в apk/fossRelease,
# со splits — в apk/foss/release. Ищем по всему дереву, чтобы скрипт не разъезжался
# с конфигурацией сборки.
APK="$(find android/build/outputs/apk -name '*-release*.apk' | head -1)"
[ -n "$APK" ] || { echo "APK не найден в android/build/outputs/apk" >&2; exit 1; }
echo "== Собрано: $APK"
sha256sum "$APK"

# Паспорт сборки: по нему сборка сопоставляется с исходниками без переписки.
BUILD_INFO="${APK%.apk}.build-info.txt"
{
    echo "fork_commit=$FORK_COMMIT"
    echo "overlay_commit=$OVERLAY_COMMIT"
    echo "node_baked=$NODE_HOST_BAKED"
    echo "node_ca_sha256=$(baked "$NODE_CA")"
    echo "release_key_sha256=$(baked "$NODE_KEY")"
    echo "version_name=$(grep -E '^android.version_name=' gradle.properties | cut -d= -f2)"
    echo "version_code=$(grep -E '^android.version_code=' gradle.properties | cut -d= -f2)"
    echo "apk_sha256=$(sha256sum "$APK" | cut -d' ' -f1)"
    for lib in "$LIBS_DIR"/*.so; do
        echo "native_$(basename "$lib")=$(sha256sum "$lib" | cut -d' ' -f1)"
    done
    echo "java=$(java -version 2>&1 | head -1)"
    echo "gradle=$(./gradlew --version | grep -E '^Gradle' | head -1)"
} > "$BUILD_INFO"
echo "== Паспорт сборки: $BUILD_INFO"
cat "$BUILD_INFO"

cat <<'NEXT'

== Подпись (ручной шаг на доверенной машине, ТЗ §8.4)
   Ключ офлайновый и в CI его нет. Сейчас это JKS на рабочей машине:

   apksigner sign --ks keys/admin/hearth-release.jks --ks-key-alias hearth \
     --ks-pass file:keys/admin/hearth-release.pass \
     --key-pass file:keys/admin/hearth-release.pass \
     --out hearth-<версия>-arm64-v8a.apk <apk>

   apksigner verify --print-certs hearth-<версия>-arm64-v8a.apk
   # отпечаток обязан совпасть с тем, что уже стоит на устройствах семьи:
   # подпись другим ключом Android отвергнет как «приложение не установлено»

   Целевое состояние — hardware-backed ключ (YubiKey/pkcs11), тогда --ks NONE
   --ks-type PKCS11 с провайдером SunPKCS11.

== Раскатка (обновление по воздуху, patches/0011)
   1. ./verify-apk.sh hearth-<версия>-arm64-v8a.apk
   2. Положить APK на узел в updates_dir (по умолчанию /srv/hearth/updates),
      владелец hearth:hearth, права 0640.
   3. Переписать рядом manifest.json: versionName, versionCode, sha256, file.
      Писать через временный файл и mv — клиент не должен прочитать половину.
   4. Убрать предыдущий APK: манифест указывает ровно на один файл.
   5. Тестовое устройство — сутки (ТЗ §10.6 п.3), только потом остальным.

   versionCode обязан строго расти: по нему клиент решает, новее ли сборка.
NEXT
