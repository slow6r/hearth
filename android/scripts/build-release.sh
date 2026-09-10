#!/usr/bin/env bash
# Релизная сборка Android-клиента (ТЗ §8.4).
#
# Подпись здесь НЕ выполняется: ключ подписи офлайновый и hardware-backed (YubiKey/
# pkcs11), в CI его нет, подпись — отдельный ручной шаг на доверенной машине.
set -euo pipefail

FORK_DIR="${FORK_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../simplex-chat" && pwd)}"

# Overlay раскладываем сами: файлы форка лежат в этом репозитории, и собирать до
# синхронизации — значит собрать сборку без части правок и не заметить этого.
bash "$(dirname "${BASH_SOURCE[0]}")/sync-overlay.sh"

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
./gradlew clean :android:assembleFossRelease \
    -Pandroid.injected.build.abi=arm64-v8a \
    --no-daemon

APK="$(find android/build/outputs/apk/fossRelease -name '*.apk' | head -1)"
echo "== Собрано: $APK"
sha256sum "$APK"

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
