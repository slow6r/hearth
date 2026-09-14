# Серия патчей iOS поверх upstream

Те же правила, что у Android ([../../android/patches/README.md](../../android/patches/README.md)):
каждое изменение — отдельный коммит в ветке форка `hearth/<tag>`, здесь лежат
**описания** (что, почему, как найти точку интеграции `rg`-запросом, чем проверяется),
а не `.patch`-файлы. Сами коммиты выгружаются в `android/fork-patches/` — форк у
Android и iOS общий, simplex-chat это один монорепозиторий.

Одно отличие от Android: **Haskell тронут**, ровно в одном месте и по
[ADR 0016](../../docs/adr/0016-own-push-server.md). Разрешённые файлы перечислены в
[haskell-allowlist.txt](haskell-allowlist.txt); `android/scripts/rebase-upstream.sh`
останавливается на любом другом `.hs` и печатает дифф разрешённых для чтения глазами.

| # | Коммит | Файлы upstream | Статус |
|---|---|---|---|
| 0101 | [Адрес push-сервера из окружения](0101-ntf-servers-from-env.md) | `src/Simplex/Chat/Library/Commands.hs` | сделано |
| 0102 | [Идентификаторы, команда, имя](0102-branding.md) | pbxproj, entitlements, Info.plist, `AppGroup.swift`, `KeyChain.swift`, `BGManager.swift`, `*InfoPlist.strings` | сделано |
| 0103 | [Узел в сборке и окружение ядра до `haskell_init`](0103-core-environment.md) | `SimpleXApp.swift`, `NotificationService.swift`, `ShareModel.swift` | собрано (симулятор, ядро-заглушка) |
| 0104 | [Экран кода доступа перед онбордингом](0104-access-code.md) | `OnboardingView.swift` | собрано (симулятор, ядро-заглушка) |
| 0105 | [Свои серверы после создания профиля, операторы выключены](0105-own-servers.md) | `CreateProfile.swift`, `OnboardingView.swift`, `SimpleXAPI.swift`, `NetworkAndServers.swift`, `ContentView.swift` | собрано (симулятор, ядро-заглушка) |
| 0106 | [ICE: только свой coturn](0106-ice.md) | `WebRTCClient.swift`, `CallSettings.swift` | собрано (симулятор, ядро-заглушка) |
| 0107 | Тексты про push-сервер SimpleX на экране уведомлений | `NotificationsView.swift` | не начато |
| 0108 | [Дефолты: приватный роутинг, блокировка](0108-defaults.md) | `AppGroup.swift`, `ContentView.swift` | собрано (симулятор, ядро-заглушка) |
| 0109 | Ссылки на публичную сеть и сайт SimpleX, экран «О программе» с AGPLv3 | настройки, «Что нового», справка | не начато |

«Ядро-заглушка» значит: Swift-код собран в составе проекта, а вместо Haskell-ядра
линковались пустые библиотеки. На устройстве и с настоящим ядром ничего не запускалось
(`ios/README.md`, «Что уже проверено»).
