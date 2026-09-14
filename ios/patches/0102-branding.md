# 0102 — Идентификаторы, команда, имя

## Что делаем

| Что | upstream | Hearth |
|---|---|---|
| Приложение | `chat.simplex.app` | `ru.myhearth.chat` — как `applicationId` Android |
| NSE | `chat.simplex.app.SimpleX-NSE` | `ru.myhearth.chat.nse` |
| Share Extension | `chat.simplex.app.SimpleX-SE` | `ru.myhearth.chat.share` |
| Фреймворк ядра | `chat.simplex.SimpleXChat` | `ru.myhearth.chat.core` |
| UI-тесты | `chat.simplex.Tests-iOS` | `ru.myhearth.chat.tests` |
| Команда | `5NN7GUYB6T` | `5T376DA4G7` |
| App Group | `group.chat.simplex.app` | `group.ru.myhearth.chat` |
| Keychain | `…chat.simplex.app` | `5T376DA4G7.ru.myhearth.chat` |
| Фоновая задача | `chat.simplex.app.receive` | `ru.myhearth.chat.receive` |
| Имя на экране | SimpleX | Hearth (`CFBundleDisplayName`, локализованные `CFBundleName`) |

Из entitlements приложения убраны:
- `associated-domains` — universal links `simplex.chat` и `*.simplex.im` вели бы в наше
  приложение ссылки чужой сети;
- `networking.multicast` и `user-assigned-device-name` — нужны только подключению к
  десктопу по локальной сети, и оба Apple выдаёт команде по отдельной заявке.

## Почему
ТЗ §8.2 п.8 и [ADR 0015](../../docs/adr/0015-ios-client-app-store.md). Свои
идентификаторы — чтобы приложение стояло рядом со стоковым SimpleX и не делило с ним
App Group, то есть базу и ключи.

## Что осознанно не тронуто
- `PRODUCT_NAME = SimpleX`: от него зависит имя Swift-модуля, а менять его — значит
  получать конфликт в каждом файле при каждом ребейзе. Пользователь видит
  `CFBundleDisplayName`.
- Метки очередей и ключи атрибутов вида `chat.simplex.app.*` в Swift — внутренние имена,
  наружу не видны.
- Копирайты upstream — они про авторство кода, которое не изменилось.
- `SimpleX Localizations/*.xcloc` — это выгрузка для переводчиков, в сборку не входит.
  Если кто-то запустит `scripts/ios/import-localizations.sh`, имена вернутся: после
  импорта повторить замену.
- Схема `simplex:` в `CFBundleURLTypes` — решается в 0109 вместе с видом ссылок.

## Точка интеграции
```bash
rg -n "chat\.simplex\.app|5NN7GUYB6T|group\.chat\.simplex" apps/ios \
   --glob '!*.xcloc' --glob '!*Localizations*'
```
Совпадения допустимы только в метках очередей и именах внутренних файлов (см. выше).

## Что требует действий в аккаунте Apple
- Зарегистрировать пять bundle ID и App Group `group.ru.myhearth.chat`.
- `com.apple.developer.usernotifications.filtering` у NSE — выдаётся по заявке. Без неё
  убрать ключ из `SimpleX NSE.entitlements`: уведомления будут, но NSE не сможет скрыть
  пустое.

## Проверка
- Сборка ставится рядом со стоковым SimpleX.
- `plutil -lint` на всех entitlements и Info.plist.
