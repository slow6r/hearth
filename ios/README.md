# ios/ — конфиг-форк iOS-клиента

Приложение Hearth для iPhone: клиент SimpleX, который знает домашний узел, пускает по
коду доступа, не ходит на публичные серверы и получает уведомления через push-сервер
узла. Раздаётся через App Store по ссылке ([ADR 0015](../docs/adr/0015-ios-client-app-store.md)),
уведомления — [ADR 0016](../docs/adr/0016-own-push-server.md).

Пока приложения нет в App Store, iPhone настраивается по [чек-листу](../docs/ios-checklist.md).

## Что здесь

```
ios/
├── overlay/   Swift-файлы, которые форк ДОБАВЛЯЕТ
│   ├── SimpleXChat/Hearth/   логика без UI: код, узел, bundle, ICE, клиент к узлу — во фреймворк ядра
│   ├── Shared/Hearth/        экраны и применение bundle — в приложение
│   ├── Package.swift, Tests/ только для `swift test`, в форк не едут
├── patches/   описания правок в файлах upstream + список разрешённого Haskell
├── scripts/   build-core, bake-node, sync-overlay, pbx-add, build-release
└── UPSTREAM   пинованный тег
```

Сам форк — тот же, что у Android: `simplex-chat` это монорепозиторий, `apps/ios` и
`apps/multiplatform` живут в одной ветке `hearth/<tag>` (`android/FORK.md`). Коммиты
iOS выгружаются в `android/fork-patches/` тем же `export-fork-patches.sh`.

## Чем iOS отличается от Android

| | Android | iOS |
|---|---|---|
| Ядро Haskell | `.so` из официального APK с проверкой хеша | **собираем сами** (`build-core.sh`): upstream не публикует iOS-библиотеки |
| Haskell в диффе | 0 строк | одно место — адрес push-сервера ([0101](patches/0101-ntf-servers-from-env.md)) |
| Доставка | foreground-сервис, без пушей | APNs через свой `ntf-server` на узле |
| Обновления | с узла, подписанный манифест | App Store; канал узла не используется |
| Раздача | APK кому угодно, вход по коду | App Store по ссылке, вход по коду |
| Регистрация файлов | Gradle видит каталог | каждый файл вписывается в `project.pbxproj` (`pbx-add.py`) |

## Сборка

Порядок важен: ядро и вшитый узел должны существовать до первой сборки проекта.

```bash
# 0. дерево форка — android/FORK.md, «Как восстановить дерево сборки»

# 1. ядро (часы при первом прогоне)
ios/scripts/build-core.sh device     # для телефона — только Mac на Apple Silicon
ios/scripts/build-core.sh sim        # симулятор — годится и Intel

# 2. узел: адрес device API, CA и адрес push-сервера (печатает relays/ntf/init-ntf.sh)
ios/scripts/bake-node.sh relay.myhearth.ru 7444 'ntf://<fp>@relay.myhearth.ru:2053'

# 3. overlay в форк и в project.pbxproj
ios/scripts/sync-overlay.sh

# 4. закоммитить в форке и перевыпустить патчи — иначе сборка откажется
git -C android/simplex-chat add -A apps/ios src && git -C android/simplex-chat commit
android/scripts/export-fork-patches.sh

# 5. архив, IPA, загрузка
ASC_KEY_ID=… ASC_ISSUER_ID=… ASC_KEY_PATH=…/AuthKey_….p8 \
  ios/scripts/build-release.sh <номер-сборки> --upload
```

Ключ App Store Connect API в репозитории не лежит и в скрипты не зашит — только
окружение. Подпись автоматическая, команда `5T376DA4G7`.

Логику без ядра и без Xcode проверяет пакет:

```bash
cd ios/overlay && swift test
```

## Один раз в аккаунте Apple

Это делает человек: API App Store Connect создать приложение не умеет.

1. **Identifiers:** `ru.myhearth.chat`, `ru.myhearth.chat.nse`, `ru.myhearth.chat.share`,
   `ru.myhearth.chat.core`; App Group `group.ru.myhearth.chat`. У приложения — Push
   Notifications и App Groups, у NSE и Share Extension — App Groups.
2. **Заявка на `com.apple.developer.usernotifications.filtering`** для NSE. Пока её нет,
   ключ надо убрать из `SimpleX NSE.entitlements`, иначе подпись не пройдёт.
3. **Ключ APNs** для `ntf-server` на узле — [docs/runbook-ntf.md](../docs/runbook-ntf.md).
4. **App Store Connect → новое приложение:** имя Hearth, bundle `ru.myhearth.chat`.
   Приватность: сбора данных нет. Шифрование: ответить на вопросы export compliance.
5. **Для ревью:** одноразовый код `hearthctl invite create --uses 1 --note "App Review <версия>"`
   в заметках для ревьюера; после решения — `invite revoke` и `device revoke`.
6. **Unlisted:** заявка Apple на распространение по ссылке — после того как приложение
   прошло ревью.

## Что уже проверено и что нет

| Что | Состояние |
|---|---|
| Ребрендинг: идентификаторы, команда, entitlements, `plutil -lint` | проверено |
| `pbx-add.py`: регистрирует файлы, повторный запуск ничего не меняет, проект разбирается | проверено на копии |
| SPM-зависимости проекта тянутся Xcode 26.2 | проверено |
| `swift test` логики overlay: код, узел, bundle, ICE, TURN, порт релея, окружение ядра, клиент к узлу с пиннингом CA | проверено: 96 тестов, 0 падений (2026-09-14, Intel, Xcode 26.2) |
| Swift-правки 0103–0108 компилируются в составе проекта: приложение, NSE, Share Extension, фреймворк | проверено для симулятора x86_64: `BUILD SUCCEEDED`, ядро подменено пустыми библиотеками и `-undefined dynamic_lookup` — символы Haskell не проверялись |
| Приложение запускается и проходит онбординг | **нет**: нужно настоящее ядро |
| `build-core.sh` | **нет**: нужен nix, первый прогон — часы |
| Подпись, архив, загрузка | **нет**: нужны идентификаторы в аккаунте Apple |
| Пуши end-to-end | **нет**: нужен `ntf-server` на узле и ключ APNs |
