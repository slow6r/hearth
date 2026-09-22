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
```

Если Apple Silicon под рукой нет, ядро для телефона собирает GitHub Actions —
`.github/workflows/ios-core.yml`, раннер `macos-15` (он arm64). Запуск вручную,
секретов workflow не требует: подпись и загрузка остаются на машине владельца.
Артефакт распаковывается в дерево форка, после чего проект узнаёт новые имена
библиотек:

```bash
gh run download <id> -n hearth-ios-core-device -D /tmp/core
cp -R /tmp/core/ios android/simplex-chat/apps/ios/Libraries/
(cd android/simplex-chat && sh scripts/ios/update-pbxproj.sh)
```

```bash
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
| Приложение запускается и проходит онбординг | **нет**: сборка есть, на живом телефоне не проверялась |
| `build-core.sh` | проверено 2026-09-21: GitHub Actions, `macos-15`, 3 ч 7 мин, ядро arm64 с патчем 0101 внутри |
| Подпись, архив, загрузка | проверено: сборки 1, 2 и 3 приняты App Store Connect (VALID) |
| Отправка на ревью | сборка 2 отклонена как INVALID_BINARY без объяснений; в 3 закрыты манифесты конфиденциальности и `CFBundleIconName` |
| Иконка | своя: костёр из `hearth_icon_foreground.xml`, обе — основная и альтернативная в «Оформлении» |
| Пуши end-to-end | **нет**: `ntf-server` на узле не поднят, ключа APNs нет — сборка 1 выпущена без push (`bake-node.sh --no-ntf`) |
| Пины сходятся: `ios/UPSTREAM` = `android/UPSTREAM` = `v7.0.1`, а `simplexmq_core_commit` — тот же `efaad8e7…`, что в `cabal.project` форка | проверено 2026-09-19 |
| Точки интеграции патчей 0101–0108 существуют в `apps/ios` пинованного тега | проверено 2026-09-19, все восемь |
| Публичные STUN/TURN в `apps/ios/Shared` upstream присутствуют — значит патч 0106 всё ещё нужен и бьёт по живому | проверено 2026-09-19 |

## Манифест конфиденциальности

С мая 2024 Apple отклоняет сборки без `PrivacyInfo.xcprivacy` (`ITMS-91053`). В
`apps/ios` его нет ни в одной цели — ни у upstream, ни, соответственно, у нас, — и
первая отправка на ревью вернулась как «Ошибка двоичного файла» без подробностей.

Манифесты добавлены в четыре цели: приложение, `SimpleXChat`, NSE и Share Extension.
Объявлено то, что действительно есть в коде, а не шаблон:

| Категория | Причина | Где в коде |
|---|---|---|
| `UserDefaults` | `CA92.1` | 64 файла, `@AppStorage` и `UserDefaults` |
| `FileTimestamp` | `C617.1` | `SimpleXChat/FileUtils.swift`, `MigrateFromDevice.swift` |
| `SystemBootTime` | `35F9.1` | `SimpleXApp.swift`, `ContentView.swift` — `ProcessInfo.systemUptime` |

Свободное место на диске и список активных клавиатур приложение не трогает — эти
категории намеренно не объявлены: лишнее в манифесте Apple считает такой же ошибкой,
как недостающее. Проверять при обновлении upstream: список API мог измениться.

Там же добавлен верхнеуровневый `CFBundleIconName` в `SimpleX--iOS--Info.plist` — в
собранном бандле он был только внутри словаря `CFBundleIcons`, а Apple требует
отдельный ключ (`ITMS-90713`).

## Подпись: ловушка errSecInternalComponent

`xcodebuild -exportArchive` падает с `errSecInternalComponent` на пересборке подписи
фреймворка, если закрытый ключ лежит в системной связке `login.keychain-db`: `codesign`
просит подтверждения, а в неинтерактивной сессии подтвердить некому. Архив при этом
собирается успешно — ошибка вылезает только на экспорте, и это сбивает с толку.

Лечится отдельной связкой, пароль от которой известен скрипту, без пароля пользователя
от системной:

```bash
security create-keychain -p "$KP" hearth-signing.keychain-db
security set-keychain-settings -lut 21600 hearth-signing.keychain-db
security unlock-keychain -p "$KP" hearth-signing.keychain-db
security import distribution.p12 -k hearth-signing.keychain-db -P "$P12" \
    -T /usr/bin/codesign -T /usr/bin/security -A
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KP" \
    hearth-signing.keychain-db
security list-keychains -d user -s hearth-signing.keychain-db login.keychain-db
```

`set-key-partition-list` здесь главный: без него импорт с `-A` всё равно оставляет ключ
недоступным для `codesign`. Второй обязательный шаг — `set-keychain-settings` **без**
флагов: по умолчанию связка блокируется при засыпании ноутбука, и следующий экспорт
падает с тем же `errSecInternalComponent`, хотя архив снова собирается успешно.

## Что из этого проверяется без Mac

Не всё здесь требует macOS, и это стоит знать: половина проверок — про согласованность
репозитория с форком, а не про сборку.

Без Mac проверяются: совпадение пинов между `ios/UPSTREAM`, `android/UPSTREAM` и
`cabal.project` форка; наличие точек интеграции из `patches/*.md` в дереве пинованного
тега (в каждом описании для этого лежит готовый `rg`-запрос); синтаксис `pbx-add.py`;
что цель патча 0106 ещё на месте, то есть публичные STUN/TURN в upstream не исчезли
сами. Это и есть проверка «описания патчей не протухли» — ровно то, ради чего
`patches/` хранит намерение и запрос поиска, а не `.patch` с фиксированными
контекстами.

Требуют Mac и ничем не заменяются: `swift test`, `build-core.sh`, `xcodebuild` и всё,
что за ним — архив, IPA, загрузка в App Store Connect.

Отдельно: `scripts/sync-overlay.sh` для iOS намеренно НЕ гоняется на рабочей станции
без нужды. Он кладёт в `apps/ios` новые файлы, дерево форка становится грязным, и
`android/scripts/build-release.sh` отказывается собирать Android — гейт «только из
чистого дерева» не различает, чей overlay разложен. Раскладывать перед сборкой iOS, на
той машине, где она идёт.
