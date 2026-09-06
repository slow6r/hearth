# 0005 — Манифест: безопасные дефолты

## Что делаем
В `AndroidManifest.xml` мержим фрагмент `overlay/android/src/main/AndroidManifest-hearth.xml`:
`allowBackup="false"`, `dataExtractionRules`, `networkSecurityConfig`, удаление
разрешений FCM/геолокации через `tools:node="remove"`.

## Почему
ТЗ §3.1 «Утечка через бэкапы ОС» и §8.2 п.6. База приложения содержит историю сообщений
и учётные данные релея; копия этого у Google — ровно та зависимость, которую проект
устраняет.

## Точка интеграции
`apps/multiplatform/android/src/main/AndroidManifest.xml` — атрибуты `<application>`
плюс два ресурса в `res/xml/`.

## Проверка
- A9: `adb backup` не содержит данных приложения.
- A5: `apkanalyzer dex packages` — нет `com.google.android.gms` / `com.google.firebase`.
- `scripts/verify-apk.sh` проверяет оба пункта плюс `allowBackup` в собранном APK.
