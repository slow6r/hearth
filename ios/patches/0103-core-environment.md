# 0103 — Узел в сборке и окружение ядра до `haskell_init`

## Что делаем
В каждом из трёх процессов — приложение, NSE, Share Extension — перед `haskell_init*`
вызывается `HearthCoreEnvironment.prepare(node:)`. Он выставляет `HEARTH_NTF_SERVERS`
из вшитого `hearth_node.json` (поле `ntf`) или пустую строку, если адреса нет или он
не прошёл проверку.

## Почему
0101: ядро читает адрес push-сервера один раз, при создании контроллера. NSE — отдельный
процесс со своим ядром: пропустить его значит получить пуши, которые расширение не
сможет расшифровать, а в худшем случае — без `0101` — серверы SimpleX.

Адрес вшивается, а не приходит с bundle: первый запуск ядра случается раньше `/claim`.

## Точка интеграции
```bash
rg -n "haskell_init(_nse|_se)?\(\)" apps/ios --glob '*.swift'
```
Три вызова: `Shared/SimpleXApp.swift` (`init`), `SimpleX NSE/NotificationService.swift`
(`doStartChat`), `SimpleX SE/ShareModel.swift` (`initChat`). Ресурсы узла лежат во
фреймворке `SimpleXChat` (`SimpleXChat/Hearth/Resources`) — единственном бандле, который
видят все три процесса; искать их через `Bundle(for: HearthNodeClient.self)`.

## Проверка
- `HearthCoreEnvironmentTests` (`swift test` в `ios/overlay`): пустое значение для
  отсутствующего и невалидного адреса.
- Ручная: сборка без `bake-node.sh` → экран кода говорит «сборка неполная».
