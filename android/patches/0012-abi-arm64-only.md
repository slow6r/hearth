# 0012 — Только arm64-v8a, и почему не флагом

## Что делаем
Ограничение ABI переносим из командной строки в `android/build.gradle.kts`: один
`include("arm64-v8a")` вместо `-Pandroid.injected.build.abi=arm64-v8a` при вызове
gradle.

## Почему
Две причины, и вторая — та, из-за которой это отдельный патч.

**По существу.** ТЗ §8.4: релиз только arm64-v8a. 32-битных устройств в семье нет, а
нативное ядро мы не собираем ([README](../README.md), «Стратегия») — берём `.so` из
релизного APK upstream, и там лежит только arm64-v8a. Сборка `armeabi-v7a` падает на
отсутствии библиотек.

**По механике.** `android.injected.*` — это namespace, которым Android Studio
сообщает «деплой на вот это подключённое устройство». Увидев его, AGP помечает APK
`android:testOnly="true"`, и Android отказывается ставить такой файл обычным
способом: «приложение предназначено только для тестирования, установите официальную
версию». Устанавливается он лишь через `adb install -t`, что для раздачи семье не
годится.

Поймано ровно так: сборка 373 собралась, подписалась, прошла `verify-apk.sh` — и не
встала на телефон. Проверка на `testOnly` добавлена в `verify-apk.sh`, чтобы это не
повторилось: собранный APK, который нельзя установить, обязан падать на проверке, а
не у человека в руках.

## Точка интеграции
```bash
rg -n "splits|abiFilters" apps/multiplatform/android/build.gradle.kts
```

Upstream держит два ABI и раскладывает их по отдельным APK. Оставляем один include в
обеих ветках (`isBundle` и `splits`), `isUniversalApk = false`.

## Проверка
- `aapt2 dump xmltree --file AndroidManifest.xml <apk> | rg testOnly` — пусто.
- `scripts/verify-apk.sh`: секции «testOnly» и «ABI».
- `aapt2 dump badging <apk> | rg native-code` — только `arm64-v8a`.
