# docs/

| Файл | Что внутри |
|---|---|
| [tz.md](tz.md) | Исходное ТЗ v1.2. Ссылки «ТЗ §5.4» ведут сюда. Где реализация от него отступила — см. ADR, в первую очередь [0007](adr/0007-public-relay-no-vpn.md) |
| [architecture.md](architecture.md) | Как это устроено и почему именно так |
| [acceptance-tests.md](acceptance-tests.md) | A1–A13 с конкретными командами |
| [ios-checklist.md](ios-checklist.md) | Ручная настройка стокового клиента |
| [open-questions.md](open-questions.md) | Что осталось решить |
| [deploy-fels-2026-09-09.md](deploy-fels-2026-09-09.md) | Журнал развёртывания на `fels`: что сделано, что найдено по дороге, что осталось |

## Runbook'и

| Файл | Когда открывать |
|---|---|
| [runbook-deploy.md](runbook-deploy.md) | Разворачиваем узел: сеть, проброс портов, релеи, звонки |
| [runbook-install-beelink.md](runbook-install-beelink.md) | Установка на конкретную машину: Debian 13, LUKS, два пользователя, зал |
| [runbook-router-udm.md](runbook-router-udm.md) | Всё, что делается на роутере: проверка статики адреса, DNS-запись, проброс портов |
| [runbook-migration.md](runbook-migration.md) | Переезд ПК → mini-PC без смены адреса (§10.2) |
| [runbook-device-add.md](runbook-device-add.md) | Новое устройство в семье (§10.3) |
| [runbook-device-lost.md](runbook-device-lost.md) | Телефон потерян или украден (§10.4) |
| [runbook-rotate-address.md](runbook-rotate-address.md) | Компрометация CA или пароля релея (§10.5) |
| [runbook-updates.md](runbook-updates.md) | Обновление компонентов (§10.6) |
| [runbook-restore-drill.md](runbook-restore-drill.md) | Квартальная проверка восстановления (§10.7) |

## Решения (ADR)

| ADR | Решение |
|---|---|
| [0001](adr/0001-rust-scope.md) | Что именно пишем на Rust, а что не трогаем |
| [0002](adr/0002-systemctl-instead-of-zbus.md) | `systemctl` вместо `zbus` |
| [0003](adr/0003-named-nft-counters.md) | Именованные счётчики nftables вместо анонимных |
| [0004](adr/0004-fingerprint-auth.md) | Авторизация админа по отпечатку сертификата, не по CN |
| [0005](adr/0005-no-http-client.md) | Свой минимальный HTTP вместо клиентского крейта |
| [0006](adr/0006-state-dir-in-backup.md) | Четвёртый каталог в бэкапе сверх трёх из §10.1 |
| [0007](adr/0007-public-relay-no-vpn.md) | **Публичный релей вместо доступа только через WireGuard** |
| [0008](adr/0008-multi-purpose-host.md) | **Многоцелевой узел: egress по пользователям** |
| [0009](adr/0009-no-full-disk-encryption.md) | Узел без LUKS: принятое отступление |
| [0010](adr/0010-device-api.md) | **Device API: публичный сервис узла для самих телефонов** |

## Как читать код

Точка входа — `hearthd/src/lib.rs`: там перечислены модули и сказано, чего `hearthd`
не делает никогда. Дальше по модулям:

- `net.rs` — egress-политика, код-двойник output-цепочки nftables;
- `egress/` — детектор исходящих соединений узла;
- `model/bundle.rs` — форматы адресов и ICE, сверенные с исходниками upstream v7.0.1;
- `configgen/turn.rs` — почему TURN-credential приходится подбирать, а не просто считать;
- `migrate/` — переезд железа без смены адреса релея.

## Что сверялось с upstream

Реализация опирается на исходники `simplexmq` / `simplex-chat` **v7.0.1**, а не на
догадки. Проверенные факты, каждый из которых влияет на код:

| Факт | Где в upstream | Что из этого следует |
|---|---|---|
| `[TRANSPORT] host` — «only used to print server address on start» | `Server/Main/Init.hs` | Релей слушает все интерфейсы; ограничение адресов — задача nftables, а не ini |
| Дефолт портов `5223,443` | `Server/Main/Init.hs` | 443 держим: он пробивает ограниченные сети. Нужен `CAP_NET_BIND_SERVICE` |
| TTL сообщений по умолчанию 21 день | `Server/Env/STM.hs` | Совпадает с окном ротации адреса |
| ICE задаётся строкой `turn:user:cred@host:port` | `views/call/WebRTC.kt` | Bundle отдаёт строки, а не объекты; ТЗ Приложение B здесь неточно |
| `parseRTCIceServers` возвращает `null` для всего списка при одной плохой записи, и клиент откатывается на публичные STUN/TURN | `views/call/WebRTC.kt` | Одна кривая строка = молчаливая утечка на третью сторону. Отсюда строгая валидация с обеих сторон |
