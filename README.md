# hearth

Закрытый семейный мессенджер на базе SimpleX на собственном домашнем железе.
Свой релей, свой TURN для звонков, свои клиенты. Без чужих релеев, без магазинов
приложений, без номеров телефонов, без пуш-инфраструктуры Google/Apple. До 20 устройств.

Релеи и TURN доступны из интернета — как любой сервер SimpleX. На LAN остаются только
admin API и ssh. Обоснование и цена решения:
[ADR 0007](docs/adr/0007-public-relay-no-vpn.md).

Исходное задание: [docs/tz.md](docs/tz.md). Ссылки вида «ТЗ §5.4» ведут туда; места,
где реализация от него отступила, перечислены в [ADR](docs/adr/).

---

## Главная идея

Криптопротокол и релеи — стоковый upstream SimpleX, **ни одной изменённой строки**.
Содержимое защищено E2E-шифрованием, отпечаток CA релея зашит в клиентский адрес —
этого достаточно, чтобы сервер стоял на публичном адресе.

Что проект добавляет поверх: **узел ничего не инициирует сам**. Клиенты подключаются
внутрь; исходящих соединений у узла быть не должно, и любая попытка их открыть попадает
в счётчик nftables, в журнал и в постоянную историю инцидентов.

Ожидаемое значение `egress_drop` за сутки — **ноль**. Не «мало» — ноль. Единственное
исключение — медиапоток coturn, разрешённый точечно по владельцу сокета и диапазону
портов: без него звонок между двумя устройствами за NAT не состоится.

---

## Что в репозитории

```
hearth/
├── hearthd/     Rust control plane: supervisor, egress-watchdog, integrity,
│                backup, config-gen, admin API, migrate + CLI hearthctl
├── relays/      конфиги и init-скрипты стоковых релеев. Кода upstream здесь нет
├── android/     overlay-файлы и серия патчей конфиг-форка (сам форк — submodule)
├── docs/        ТЗ, архитектура, runbook'и, ADR, acceptance-тесты
├── tests/       acceptance-скрипты для узла
└── keys/        только публичные ключи (allow-list .gitignore)
```

Единственный написанный здесь код — `hearthd` и Kotlin-обвязка форка. Всё остальное —
конфигурация, процедуры и проверки.

---

## Быстрый старт

### Собрать

```bash
cd hearthd
cargo test                                   # 167 тестов, включая e2e admin API
cargo clippy --all-targets -- -D warnings
cargo build --release --target x86_64-unknown-linux-musl
```

Статический musl-бинарь: на узле нет ни glibc-зависимостей, ни динамического загрузчика.

### Развернуть узел

Полная процедура — [docs/runbook-deploy.md](docs/runbook-deploy.md). Кратко:

```bash
sudo hearthd/deploy/install.sh    # пользователи, каталоги, юниты, nftables

cd relays && ./smp/init-smp.sh && ./xftp/init-xftp.sh
hearthctl manifest pin --name smp-server --version <tag>
hearthd ca init && hearthd ca issue owner
hearthctl rotate turn-secret
systemctl enable --now smp-server xftp-server coturn hearthd

sudo tests/acceptance/run-all.sh   # A1, A2, A3, A4, A12
```

Обязательно до старта: проброс портов на роутере (5223, 443, 5443, 3478,
49160-49200/udp) и `node.host` в конфиге — публичное имя или адрес.

### Подключить устройство

```bash
hearthctl device add "Мама — Pixel 8"     # QR прямо в терминале
```

Дальше — [docs/runbook-device-add.md](docs/runbook-device-add.md). Цель — 5 минут.

---

## hearthctl

```bash
hearthctl health                   # состояние сервисов
hearthctl status                   # health + egress + integrity + backup + устройства
hearthctl egress                   # счётчик, который обязан быть нулём
hearthctl egress --incidents       # постоянная история инцидентов
hearthctl alerts --severity critical
hearthctl device list|add|revoke|bundle|checklist
hearthctl backup now|status|list|restore
hearthctl migrate export|import|status
hearthctl manifest verify|pin
hearthctl rotate turn-secret
```

Всё, кроме `migrate import`, `backup restore` и `manifest pin`, идёт через admin API по
mTLS. Эти три — локальные: им нужен офлайновый age-ключ или решение человека, а демон
такого не хранит.

---

## Ключевые свойства

| Свойство | Как обеспечено | Чем проверяется |
|---|---|---|
| Узел ничего не инициирует сам | `output` policy drop + `EgressPolicy` в коде; исключение — медиа coturn по `skuid` и диапазону портов | A2, модуль `egress` |
| Звонки проходят между двумя NAT | публичный coturn, ротируемый секрет, ICE в том формате, который клиент действительно парсит | A8 |
| Админка не торчит наружу | wildcard-бинд API отвергается конфигом; LAN-подсеть + mTLS + отпечаток | A4, e2e-тест |
| Запущено то, что проверяли | sha256 против манифеста, ежечасно, fail-closed | A12 |
| Адрес релея переживает железо | CA + пароль + `node.host` переезжают архивом | A13, `migrate` |
| Бэкап нельзя прочитать с узла | age, приватный ключ офлайн | A11, квартальная проверка |
| Отзыв админа мгновенный | реестр отпечатков перечитывается на каждом соединении | e2e-тест |
| Клиент не уйдёт в публичную сеть | пустые пресеты, скрытый экран операторов, валидация bundle с обеих сторон | A5, A6 |
| Посторонний не создаст очередь | `create_password` обязателен — на публичном релее это несущий замок | A3 |

---

## Что осознанно НЕ сделано

- **Второго релея нет** (ТЗ §6.5). Узел выключен → сообщения копятся на клиентах и
  доходят при возврате.
- **Метаданные соединений не скрыты.** Публичный релей означает, что наблюдатель на
  канале видит факт и объём общения. Разбор и варианты (onion) —
  [ADR 0007](docs/adr/0007-public-relay-no-vpn.md).
- **Своего iOS-клиента нет** (ТЗ §13). Стоковое приложение + чек-лист, генерируемый
  узлом: [docs/ios-checklist.md](docs/ios-checklist.md).
- **Веб-UI у `hearthd` нет** (ТЗ §7.3). Только CLI.
- **Автообновлений нет нигде.** Обновление — осознанная процедура:
  [docs/runbook-updates.md](docs/runbook-updates.md).

---

## Отклонения от буквы ТЗ

Семь, каждое с обоснованием в [docs/adr/](docs/adr/): `systemctl` вместо `zbus`,
именованные счётчики nftables вместо анонимных, `POST /migrate/export` вместо `GET`,
четвёртый каталог в бэкапе, авторизация по отпечатку сертификата, свой минимальный HTTP
вместо клиентского крейта и — самое крупное — [публичный релей вместо доступа только
через WireGuard](docs/adr/0007-public-relay-no-vpn.md).

Отдельно: формат ICE в bundle отличается от ТЗ Приложения B. Приложение описывает объект
`{urls, username, credential}`, а клиент SimpleX парсит **строку**
`turn:user:cred@host:port`. Проверено по исходникам v7.0.1 — реализация следует за
клиентом, а не за документом.

---

## Лицензия

`hearthd` — AGPL-3.0-or-later, как и upstream SimpleX. Экран «О программе» в
Android-клиенте обязан содержать ссылку на upstream и текст AGPLv3 (ТЗ §8.2 п.8).
