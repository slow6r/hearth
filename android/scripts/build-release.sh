#!/usr/bin/env bash
# Релизная сборка Android-клиента (ТЗ §8.4).
#
# Подпись здесь НЕ выполняется: ключ подписи офлайновый и hardware-backed (YubiKey/
# pkcs11), в CI его нет, подпись — отдельный ручной шаг на доверенной машине.
set -euo pipefail

FORK_DIR="${FORK_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../simplex-chat" && pwd)}"
cd "$FORK_DIR/apps/multiplatform"

echo "== Версии инструментов (должны совпадать с gradle/libs.versions.toml)"
java -version 2>&1 | head -1
./gradlew --version | grep -E 'Gradle|JVM'

echo "== Сборка release (только arm64-v8a)"
./gradlew clean :android:assembleRelease \
    -Pandroid.injected.build.abi=arm64-v8a \
    --no-daemon

APK="$(find android/build/outputs/apk/release -name '*.apk' | head -1)"
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
