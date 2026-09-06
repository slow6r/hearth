# relays/ — конфигурация стоковых релеев

**Здесь нет ни строчки кода upstream.** Только ini-файлы, init-скрипты и процедура
проверки подписи. Любой diff к Haskell-коду SimpleX — блокер ревью (ТЗ §2.2, §8.3).

```
relays/
├── smp/        smp-server.ini.example + init-smp.sh
├── xftp/       file-server.ini.example + init-xftp.sh
├── coturn/     → hearthd/deploy/coturn/turnserver.conf.tmpl (рендерится hearthd)
└── verify-ini-keys.sh
```

---

## 1. Откуда берутся бинари (ТЗ §6.1)

`latest` запрещён. Всегда конкретный тег + sha256 в `hearthd/manifest.toml`.

**На машине с интернетом (НЕ на узле — у узла нет egress):**

```bash
TAG=v6.x.y                     # конкретный тег ветки stable
BASE=https://github.com/simplex-chat/simplexmq/releases/download/$TAG

curl -fLO $BASE/smp-server-ubuntu-22_04-x86-64
curl -fLO $BASE/smp-server-ubuntu-22_04-x86-64.asc
curl -fLO $BASE/xftp-server-ubuntu-22_04-x86-64
curl -fLO $BASE/xftp-server-ubuntu-22_04-x86-64.asc

# Ключ разработчиков SimpleX. Импортировать один раз, отпечаток сверить
# с сайтом simplex.chat и с ключом в предыдущих релизах.
gpg --verify smp-server-ubuntu-22_04-x86-64.asc  smp-server-ubuntu-22_04-x86-64
gpg --verify xftp-server-ubuntu-22_04-x86-64.asc xftp-server-ubuntu-22_04-x86-64

sha256sum smp-server-ubuntu-22_04-x86-64 xftp-server-ubuntu-22_04-x86-64
```

Подпись **должна** совпадать с `upstream.gpg_identity` из манифеста. Если подписи нет
или она не сходится — не переносите файл на узел.

Перенос на узел: USB. После установки:

```bash
install -m 0755 smp-server-ubuntu-22_04-x86-64  /usr/local/bin/smp-server
install -m 0755 xftp-server-ubuntu-22_04-x86-64 /usr/local/bin/xftp-server

hearthctl manifest pin --name smp-server  --version $TAG
hearthctl manifest pin --name xftp-server --version $TAG
```

С этого момента `hearthd` считает sha256 каждый час; несовпадение = стоп релея и
critical-алерт (ТЗ §7.3, A12).

**Альтернатива — сборка из исходников** по upstream-инструкции. Тогда в манифесте
`source = "built-from-source"`, а хеш всё равно пиннится: важно не происхождение, а то,
что запущено ровно то, что проверяли.

---

## 2. Инициализация (один раз на жизнь узла)

```bash
./smp/init-smp.sh        # создаёт CA, ключи, fingerprint, ini
./xftp/init-xftp.sh
```

Init создаёт **собственный CA релея** в `/etc/opt/simplex/`. Отпечаток этого CA —
часть адреса `smp://<fp>:<pass>@10.66.10.10:5223`, поэтому:

> Эти ключи переезжают с ПК на mini-PC. Именно они, а не железо, и есть «узел»
> (ТЗ §2.5, §10.2).

Пароли на создание очередей генерируются скриптом и кладутся в
`/etc/hearth/secrets/{smp,xftp}-create-password` (0600) — оттуда их читает `hearthd`
при сборке bundle.

---

## 3. Ini-файлы: почему `.example`, а не готовые

Имена ключей в `smp-server.ini` менялись между версиями upstream, и ТЗ §6.2 прямо
говорит «имена ключей уточнить по версии». Поэтому здесь лежит **эталон намерений**, а
источник истины — файл, который сгенерировал `smp-server init` вашего пинованного тега.

Порядок такой:

1. `smp-server init ...` генерирует настоящий ini;
2. `./verify-ini-keys.sh /etc/opt/simplex/smp-server.ini smp/smp-server.ini.example`
   показывает, какие ключи из эталона отсутствуют или называются иначе;
3. правите настоящий ini под требования ТЗ §6.2, а `.example` — под реальные имена
   ключей вашей версии, и коммитите обе правки одним коммитом.

Требования ТЗ §6.2/§6.3, которые обязаны выполняться независимо от имён ключей:

| Требование | Зачем |
|---|---|
| store log включён | сообщения переживают рестарт узла (A7) |
| restore messages включён | после возврата питания очереди восстанавливаются |
| TTL сообщений 21 день | ограничение хранения; совпадает с окном ротации адреса (§10.5) |
| пароль на создание очередей | посторонний в WG не создаст очередь (A3) |
| notification server выключен | пушей нет вообще (§3.1, §8.2 п.4) |
| control port только 127.0.0.1 | health-check hearthd, снаружи недоступен |
| private message routing включён | релей не видит, кто с кем (§6.2) |
| information page — минимум | требование AGPL, без реальных имён |
| транспортные логи — минимум, без IP | §3.1: метаданные не накапливаем |
| bind только 10.66.10.10 | A1: никаких 0.0.0.0 |

---

## 4. Обновление (ТЗ §10.6)

1. Прочитать changelog: upstream периодически режет совместимость старых версий.
2. **Сначала клиенты, потом релей.**
3. Тестовое устройство — сутки на новой версии.
4. Новые хеши в `hearthd/manifest.toml` — тем же коммитом, что и обновление.
5. Security-релиз должен попасть в контур за ≤ 7 дней (ТЗ §1.4).
