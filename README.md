# hearth

Закрытый семейный мессенджер на базе SimpleX. Всё железо — домашнее, публичных релеев
нет, магазинов приложений нет, номеров телефонов нет, пуш-инфраструктуры Google/Apple
нет. До 20 устройств, доступ — через существующий семейный WireGuard на UDM Pro.

Полное задание: [docs/tz.md](docs/tz.md). Все ссылки вида «ТЗ §5.4» ведут туда.

---

## Главная идея

Криптопротокол и релеи — стоковый upstream SimpleX, **ни одной изменённой строки**.
Доверие к чужому бинарю заменяется наблюдением за сетью (ТЗ §2.1): узел устроен так, что
попытка отправить хоть байт наружу физически не проходит, попадает в счётчик nftables,
в журнал и в постоянную историю инцидентов.

Ожидаемое значение счётчика `egress_drop` за сутки — **ноль**. Не «мало» — ноль.

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
cargo test                                   # 158 тестов, включая e2e admin API
cargo clippy --all-targets -- -D warnings
cargo build --release --target x86_64-unknown-linux-musl
```

Статический musl-бинарь: на узле нет ни glibc-зависимостей, ни динамического загрузчика.

### Развернуть узел

Полная процедура — [docs/runbook-phase0.md](docs/runbook-phase0.md). Кратко:

```bash
sudo hearthd/deploy/install.sh    # пользователи, каталоги, юниты, nftables

cd relays && ./smp/init-smp.sh && ./xftp/init-xftp.sh
hearthctl manifest pin --name smp-server --version <tag>
hearthd ca init && hearthd ca issue owner
hearthctl rotate turn-secret
systemctl enable --now smp-server xftp-server coturn hearthd

sudo tests/acceptance/run-all.sh   # A1, A2, A3, A4, A12
```

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
hearthctl egress --incidents       # постоянная история утечек
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
| Ничего не уходит наружу | nftables `output` policy drop + `EgressPolicy` в коде | A2, модуль `egress` |
| Утечка видна, а не просто заблокирована | именованные счётчики + журнал + постоянная история | `hearthctl egress` |
| Запущено то, что проверяли | sha256 против манифеста, ежечасно, fail-closed | A12 |
| Адрес релея переживает железо | CA + пароль + IP переезжают архивом | A13, `migrate` |
| Бэкап нельзя прочитать с узла | age, приватный ключ офлайн | A11, квартальная проверка |
| Отзыв админа мгновенный | реестр отпечатков перечитывается на каждом соединении | e2e-тест |
| Клиент не уйдёт в публичную сеть | пустые пресеты, скрытый экран операторов, валидация bundle с обеих сторон | A5, A6, A8 |

---

## Что осознанно НЕ сделано

- **Второго релея нет** (ТЗ §6.5). Узел выключен → сообщения копятся на клиентах и
  доходят при возврате. Резерв означал бы либо сервер вне дома (запрещено §1.2), либо
  второй адрес у всех клиентов с первого дня.
- **Без VPN мессенджер не работает** (ТЗ §14). Это дизайн, а не недоработка.
- **Своего iOS-клиента нет** (ТЗ §13). Стоковое приложение + чек-лист из 6 шагов,
  генерируемый узлом: [docs/ios-checklist.md](docs/ios-checklist.md).
- **Веб-UI у `hearthd` нет** (ТЗ §7.3). Только CLI.
- **Автообновлений нет нигде** (ТЗ §7.4, §8.2 п.9). Обновление — осознанная процедура:
  [docs/runbook-updates.md](docs/runbook-updates.md).

---

## Отклонения от буквы ТЗ

Шесть, каждое с обоснованием в [docs/adr/](docs/adr/): `systemctl` вместо `zbus`,
именованные счётчики nftables вместо анонимных, `POST /migrate/export` вместо `GET`,
четвёртый каталог в бэкапе, авторизация по отпечатку сертификата, свой минимальный HTTP
вместо клиентского крейта.

---

## Лицензия

`hearthd` — AGPL-3.0-or-later, как и upstream SimpleX. Экран «О программе» в
Android-клиенте обязан содержать ссылку на upstream и текст AGPLv3 (ТЗ §8.2 п.8).
