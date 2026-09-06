# 0001 — Пресеты серверов

## Что делаем
Список предустановленных операторов и релеев (`smp*.simplex.im`, `xftp*.simplex.im`)
заменяем на пустой. Единственный источник адресов — bundle, импортированный по QR.

## Почему
ТЗ §1.2: федерации с публичной сетью SimpleX нет; §8.2 п.1: заменить upstream-операторов
на `10.66.10.10`. Адрес релея содержит пароль (§6.2), поэтому в APK он не зашивается —
приходит с bundle.

## Точка интеграции
Модуль пресетов в `apps/multiplatform/common`. В текущем теге искать так:

```bash
rg -n "smp[0-9]*\.simplex\.im" apps/multiplatform/common/src
rg -n "presetServers|PresetServer|defaultServers" apps/multiplatform/common/src
```

Заменить значение константы на `chat.hearth.HearthPresets.presetServers` (пустой список).
Overlay-файл: `android/overlay/common/.../HearthPresets.kt`.

Важно: не удалять типы upstream и не менять сигнатуры — только значение. Тогда конфликт
при ребейзе будет одной строкой.

## Проверка
- A6: экран операторов отсутствует.
- `rg "simplex\.im" apps/` не даёт совпадений в коде клиента.
- Юнит-тест `HearthBundleTest.rejectsAPublicRelay`.
