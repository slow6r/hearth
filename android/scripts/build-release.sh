#!/usr/bin/env bash
# Релизная сборка Android-клиента (ТЗ §8.4).
#
# Подпись здесь НЕ выполняется: ключ подписи офлайновый и hardware-backed (YubiKey/
# pkcs11), в CI его нет, подпись — отдельный ручной шаг на доверенной машине.
set -euo pipefail

FORK_DIR="${FORK_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../simplex-chat" && pwd)}"
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
   apksigner sign \
     --ks-provider-class sun.security.pkcs11.SunPKCS11 \
     --ks-provider-arg /etc/hearth/pkcs11.cfg \
     --ks NONE --ks-type PKCS11 \
     --out hearth-release-signed.apk <apk>

   apksigner verify --print-certs hearth-release-signed.apk
   # отпечаток обязан совпасть с тем, что стоит на устройствах семьи

== Раскатка
   1. Положить APK в собственный F-Droid-репозиторий на hearth-node (из домашней сети).
   2. ./verify-apk.sh hearth-release-signed.apk
   3. Тестовое устройство — сутки (ТЗ §10.6 п.3).
NEXT
