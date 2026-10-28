# 0129 — без CallKit и PushKit: звонки только внутри приложения

## Что делаем
- `CallController`: нет `CXProvider`, `CXCallController` и `PKPushRegistry`;
  `useCallKit()` всегда `false`. Остались ветки upstream для выключенного «Использовать
  интерфейс iOS для звонков» — они и раньше были полным путём звонка без CallKit.
  `hasActiveCalls()` смотрит на `ChatModel.activeCall` вместо `CXCallObserver`.
- NSE: приглашение к звонку — обычное уведомление (`createCallInvitationNtf`), без
  `CXProvider.reportNewIncomingVoIPPushPayload`.
- `ContentView`: нет перезвона из «Недавних» (`INStartCallIntent`, `import Intents`).
- Настройки звонков: нет переключателей интерфейса iOS и пункта про «Не беспокоить»,
  который на этот интерфейс ссылался.
- `Info.plist`: нет фонового режима `voip` и `NSUserActivityTypes`. Режим `audio`
  оставлен — на нём держится идущий звонок, когда приложение уходит в фон.
- `project.pbxproj`: нет явной линковки `PushKit.framework`.

## Почему
App Review (сборка 7, 2026-10-04, 2.1) потребовал видео всех функций CallKit на живом
устройстве, причём «обновлённое видео к каждой отправке». Видео — это два телефона,
человек и открытый порт push-сервера (`2053`, без него входящий на заблокированный экран
не придёт). За три недели его не сняли, выпуск стоял. Без CallKit спрашивать нечего, а
звонки остаются.

Отключить CallKit только во время работы (как upstream делает в Китае) мало: символы
CallKit и режим `voip` остались бы в сборке, и вопрос мог повториться. Поэтому убрано из
бинаря целиком — проверяется `otool -L` (ниже).

## Что теряет пользователь
- Входящий на заблокированный iPhone не звонит «как телефон»: приходит уведомление о
  звонке, принять — открыв приложение. С открытым приложением — экран входящего внутри.
- Нет системного экрана звонка, зелёного индикатора и звонков в «Недавних».

Вернуть CallKit — откатить этот коммит отдельным обновлением, когда будет готово видео
(сценарий съёмки — в истории сессии 2026-10-05, коротко: исходящий, входящий при
открытом приложении, на заблокированном экране, отклонить, видео, «Недавние», запросы
микрофона, камеры и уведомлений).

## Точка интеграции
```bash
rg -n "useCallKit\(\)|import (CallKit|PushKit|Intents)|reportNewIncomingVoIPPushPayload|INStartCallIntent" apps/ios
rg -n "<string>voip</string>|NSUserActivityTypes|PushKit\.framework" apps/ios/SimpleX--iOS--Info.plist apps/ios/SimpleX.xcodeproj/project.pbxproj
```
При ребейзе на новый upstream ветки `if CallController.useCallKit()` вне контроллера можно
не трогать: они читают `false` и уходят в `else`.

## Проверка
- `otool -L SimpleX.app/SimpleX` и `otool -L SimpleX.app/PlugIns/SimpleX NSE.appex/SimpleX NSE`
  — ни `CallKit`, ни `PushKit`, ни `Intents`.
- `rg -n "import (CallKit|PushKit|Intents)" apps/ios` — пусто.
- На устройстве: звонок с открытым приложением в обе стороны; входящий при свёрнутом
  приложении — уведомление о звонке (нужен проброс `2053`).
