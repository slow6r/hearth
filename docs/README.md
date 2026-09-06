# docs/

| Файл | Что внутри |
|---|---|
| [tz.md](tz.md) | Техническое задание v1.2 — источник истины. Все ссылки вида «ТЗ §5.4» ведут сюда |
| [architecture.md](architecture.md) | Как это устроено и почему именно так |
| [acceptance-tests.md](acceptance-tests.md) | A1–A13 с конкретными командами |
| [ios-checklist.md](ios-checklist.md) | Ручная настройка стокового клиента (ТЗ §9) |
| [open-questions.md](open-questions.md) | ТЗ §15 + что всплыло при реализации |

## Runbook'и (ТЗ §10)

| Файл | Когда открывать |
|---|---|
| [runbook-phase0.md](runbook-phase0.md) | Разворачиваем узел на существующем ПК |
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

## Как читать код

Точка входа — `hearthd/src/lib.rs`: там перечислены модули и сказано, чего `hearthd`
не делает никогда. Дальше по модулям:

- `net.rs` — egress-политика, код-двойник output-цепочки nftables;
- `egress/` — детектор утечек, на котором держится вся модель доверия;
- `model/bundle.rs` — формат Приложения B, с тестами на каждое требование;
- `migrate/` — процедура §10.2, ради которой адрес релея переживает железо.
