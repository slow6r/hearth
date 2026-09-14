# Задание: push-сервер для iOS на узле fels

Для сессии, которая работает с узлом с домашнего ПК. Файл самодостаточен: команды
написаны одной строкой, пути полные. Где написано **СТОП** — дальше только после явного
«да» пользователя.

---

## 0. Что это и в каком оно состоянии

Это не план: код написан 2026-09-14 и лежит в репозитории
`https://github.com/slow6r/hearth`, ветка **`ios-app-store-push`**, PR #1 (не смержен).

| Коммит | Что |
|---|---|
| `dc0b6e0` | README |
| `cb79112` | узел: ntf-server, `[ntf]`, `egress.process_allow`, `/claim` с `platform` |
| `bd738f2`, `0d4c577` | iOS-клиент, серия патчей форка |
| следующий за ними | этот файл и исправление §6 в `docs/runbook-ntf.md` |

Забрать:

```bash
git fetch origin ios-app-store-push
git checkout ios-app-store-push
git log --oneline -6
git show origin/ios-app-store-push:docs/runbook-ntf.md | head -3
```

Если локальный `main` впереди `origin/main` (незапушенные коммиты, например по coturn) —
не мержить вслепую, сначала показать пользователю `git log --oneline origin/main..main`.

### Что проверено, а что нет

| Проверено | Не запускалось ни разу |
|---|---|
| `cargo test` (248 + 3 + 7), `cargo clippy --all-targets -- -D warnings` | `relays/ntf/build-ntf-server.sh` |
| юнит-тесты: `[ntf]` в конфиге, `process_allow`, `/claim` | `relays/ntf/init-ntf.sh` |
| | юниты `ntf-server.service`, `ntf-db-dump.*`, `var-opt-simplex-ntf.mount` на systemd |
| | синтаксис новых правил `hearth.nft` (`nft -c` на macOS нет) |
| | ntf-server ↔ PostgreSQL, роль с дефисом в строке подключения libpq |
| | `BindReadOnlyPaths` поверх `/etc/ssl/cert.pem`, если этого файла на хосте нет |

Поэтому каждый шаг ниже — с проверкой и откатом. Сломалось — чинить в репозитории
коммитом в ветку, а не руками на узле: иначе следующий `install.sh` вернёт поломку.

---

## 1. Правила

- **Можно без спроса:** читать на узле, собирать на домашнем ПК, коммитить исправления в
  ветку `ios-app-store-push`.
- **Никогда:**
  - `flush ruleset` — снесёт таблицы Docker;
  - `nft -f /etc/hearth/nftables/hearth.nft` на живом узле — в файле нет удаления
    таблицы, правила допишутся второй раз. Перезагрузка правил — только через
    `/etc/nftables.conf` (шаг 4);
  - выводить содержимое `.p8` в терминал, лог, чат;
  - класть в git ключ, `ntf.env` с реальным Key ID, пароли;
  - расширять правила фаервола «чтобы заработало».
- Узел боевой, через него работают Android-клиенты семьи. Если после шага статус узла не
  normal или сообщение с Android не проходит — **сначала откат шага**, потом разбор.
- `hearthctl status`, `health`, `egress`, `mode`, `manifest verify` ходят в admin API по
  mTLS, а ключ `owner` на узле не хранится (журнал, Э3). Эти команды — **с рабочей
  станции**, тем же способом, что обычно. На самом узле локально работают
  `hearthctl manifest pin`, `hearthd check`, `nft`, `systemctl`, `journalctl`.
  Ниже `HC` означает этот обычный вызов `hearthctl` с рабочей станции.

---

## 2. coturn и порядок работ

Ветка файлы coturn не меняет. Но **`hearthd/deploy/install.sh` при каждом запуске
безусловно перезаписывает** версиями из репозитория:

- `/etc/hearth/templates/turnserver.conf.tmpl`
- `/etc/hearth/nftables/hearth.nft`
- `/etc/systemd/system/hearthd.service`, `smp-server.service`, `xftp-server.service`,
  `ntf-server.service`, `ntf-db-dump.service`, `ntf-db-dump.timer`
- `/etc/systemd/system/coturn.service.d/hearth.conf`, `/etc/tmpfiles.d/hearth-coturn.conf`
- `/etc/polkit-1/rules.d/49-hearthd.rules`

Существующие `/etc/hearth/hearthd.toml` и `/etc/hearth/manifest.toml` он не трогает.

Следствие: ужесточение coturn делается **в репозитории** (шаблон
`hearthd/deploy/coturn/turnserver.conf.tmpl` и, если нужно, `hearth.nft`) — иначе шаг 4
его откатит. Предложение: coturn первым, отдельным коммитом в эту ветку (или в `main` и
merge в ветку до шага 4). Решает пользователь.

---

## 3. Разведка — ничего не меняя

Узел: `fels`, Debian 13, `192.168.1.72`, публичный `185.145.126.254`, имя
`relay.myhearth.ru`. SSH — по IP, имя `fels` отваливается. Ветку перенести на узел тем же
способом, что при развёртывании, целиком (`hearthd/deploy`, `relays`, `tests`). Ниже `R` —
путь к этой копии на узле.

С рабочей станции:

```bash
HC status
HC mode show
HC manifest verify
```

На узле:

```bash
sudo nft list counter inet hearth egress_drop
sha256sum /usr/local/bin/hearthd /usr/local/bin/hearthctl
cat /etc/nftables.conf
```

`/etc/nftables.conf` обязан быть без `flush ruleset` и содержать ровно эту тройку, иначе
**СТОП**:

```
table inet hearth
delete table inet hearth
include "/etc/hearth/nftables/hearth.nft"
```

Сравнить боевое с веткой:

```bash
diff -u /etc/hearth/nftables/hearth.nft R/hearthd/deploy/nftables/hearth.nft
diff -u /etc/systemd/system/hearthd.service R/hearthd/deploy/systemd/hearthd.service
diff -u /etc/systemd/system/smp-server.service R/hearthd/deploy/systemd/smp-server.service
diff -u /etc/systemd/system/xftp-server.service R/hearthd/deploy/systemd/xftp-server.service
diff -u /etc/systemd/system/coturn.service.d/hearth.conf R/hearthd/deploy/systemd/coturn.service.d-hearth.conf
diff -u /etc/tmpfiles.d/hearth-coturn.conf R/hearthd/deploy/tmpfiles/hearth-coturn.conf
diff -u /etc/polkit-1/rules.d/49-hearthd.rules R/hearthd/deploy/polkit/49-hearthd.rules
diff -u /etc/hearth/templates/turnserver.conf.tmpl R/hearthd/deploy/coturn/turnserver.conf.tmpl
diff -u R/hearthd/deploy/hearthd.toml /etc/hearth/hearthd.toml
sudo R/hearthd/deploy/install.sh --dry-run
```

Критерий. В `hearth.nft`, юнитах, polkit и шаблоне coturn допустимы только отличия,
внесённые веткой:

- `hearth.nft`: счётчики `ntf_in` и `ntf_egress`, вход `tcp dport 2053`, правило
  `meta skuid "simplex-ntf" ip daddr 17.0.0.0/8 tcp dport 443`;
- `hearthd.service`: группа `simplex-ntf` и пути ntf;
- polkit: юнит `ntf-server.service`.

Любое другое отличие значит, что файл правили на узле и не донесли в репозиторий: перенести
правку в репозиторий коммитом **до шага 4**. `hearthd.toml` отличается ожидаемо (журнал,
«Чем боевой конфиг отличается от эталона»), `install.sh` его не трогает.

Ещё на узле:

```bash
dpkg -l postgresql 2>/dev/null | tail -1
sudo ss -ltnp | grep -E ':(2053|5227|5432) '
ip route show default
command -v curl
ls -l /etc/ssl/cert.pem
```

**СТОП 1** — отчёт пользователю: результаты сравнения, что придётся донести в
репозиторий, решение по coturn.

---

## 4. hearthd из ветки; push остаётся выключенным

Сборка на домашнем ПК (WSL2 или контейнер `rust:alpine`, как в журнале Э3):

```bash
cd hearthd
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release --target x86_64-unknown-linux-musl
grep -m1 '^version' Cargo.toml
```

Резервная копия на узле (root-only: в `/etc/hearth` есть секреты):

```bash
sudo install -d -m 0700 /root/pre-ntf
sudo cp -a /usr/local/bin/hearthd /usr/local/bin/hearthctl /root/pre-ntf/
sudo tar -czf /root/pre-ntf/etc.tar.gz /etc/hearth /etc/nftables.conf /etc/systemd/system/hearthd.service /etc/systemd/system/smp-server.service /etc/systemd/system/xftp-server.service /etc/systemd/system/coturn.service.d /etc/polkit-1/rules.d/49-hearthd.rules /etc/tmpfiles.d/hearth-coturn.conf
sudo tar -xzf /root/pre-ntf/etc.tar.gz -C /root/pre-ntf etc/hearth/nftables/hearth.nft
sudo chmod -R go-rwx /root/pre-ntf
```

Порядок важен. `install.sh` ставит бинари из `hearthd/target/…` (если они там есть) и
сразу меняет юниты. Работающий hearthd, увидев бинарь не из манифеста, уведёт узел в
карантин — поэтому он останавливается до `install.sh`, а пин делается до старта:

```bash
sudo systemctl stop hearthd
sudo R/hearthd/deploy/install.sh
sudo install -m 0755 <путь к новому hearthd> <путь к новому hearthctl> /usr/local/bin/
sudo hearthctl manifest pin --name hearthd --version <version из Cargo.toml>
sudo hearthd --config /etc/hearth/hearthd.toml check
```

`install` бинарей не нужен, если `install.sh` сам поставил их из `target/` —
сверить `sha256sum /usr/local/bin/hearthd` с собранным.

Фаервол — атомарная замена таблицы через `/etc/nftables.conf`, под таймером автоотката
(как в журнале, Э4):

```bash
printf 'table inet hearth\ndelete table inet hearth\ninclude "/root/pre-ntf/etc/hearth/nftables/hearth.nft"\n' | sudo tee /root/pre-ntf/rollback.nft
sudo nft -c -f /root/pre-ntf/rollback.nft
sudo nft -c -f /etc/nftables.conf
sudo systemd-run --on-active=5min --unit=hearth-nft-rollback nft -f /root/pre-ntf/rollback.nft
sudo nft -f /etc/nftables.conf
```

Из **второго** окна: ssh на `192.168.1.72` открывается, контейнеры и cloudflared живы
(проверки как в Э4). Всё в порядке — снять таймер:

```bash
sudo systemctl stop hearth-nft-rollback.timer
```

Не в порядке — ничего не делать: через 5 минут таймер вернёт старые правила.

Замена таблицы обнуляет её счётчики; hearthd считает уменьшение счётчика сбросом, а не
инцидентом. Если `egress_drop` до шага был **не 0** — отдельный разбор до продолжения.

Запуск и проверка:

```bash
sudo systemctl start hearthd
sudo nft list counter inet hearth egress_drop
sudo R/tests/acceptance/run-all.sh
```

```bash
HC status
HC mode show
```

Android: сообщение туда и обратно.

**Откат шага 4:**

```bash
sudo systemctl stop hearthd
sudo install -m 0755 /root/pre-ntf/hearthd /root/pre-ntf/hearthctl /usr/local/bin/
sudo tar -xzf /root/pre-ntf/etc.tar.gz -C /
sudo systemctl daemon-reload
sudo nft -f /etc/nftables.conf
sudo systemctl start hearthd
```

Пользователь `simplex-ntf` после отката остаётся — он ничему не мешает.

**СТОП 2** — отчёт. Узел в стабильном состоянии: новый hearthd, `[ntf]` выключен.

---

## 5. Сборка ntf-server — на домашнем ПК, узел не трогаем

```bash
relays/ntf/build-ntf-server.sh
```

Нужен Docker с `linux/amd64` (на Windows — WSL2). Результат — `relays/ntf/dist/`:
бинарь `ntf-server`, `ntf-server.ldd`, sha256 в выводе. Первая сборка — часы. Сломается —
чинить скрипт, коммит в ветку.

**СТОП 3** — отчёт: sha256, содержимое `ntf-server.ldd`.

---

## 6. Установка без включения

Бинарь на узел тем же путём, что релеи; sha256 сверить на узле с выводом сборки.

```bash
sudo apt install postgresql
sudo install -m 0755 ntf-server /usr/local/bin/ntf-server
ldd /usr/local/bin/ntf-server | grep 'not found'
sudo ss -ltnp | grep 5432
```

`ldd … not found` обязан быть пустым (недостающее — `apt install` по `ntf-server.ldd`).
PostgreSQL слушает только `127.0.0.1`/`::1` или только сокет.

Манифест: в `/etc/hearth/manifest.toml` раскомментировать блок `ntf-server` (текст — в
`R/hearthd/manifest.toml`), затем:

```bash
sudo hearthctl manifest pin --name ntf-server --version v7.0.1+hearth.1
```

```bash
HC manifest verify
```

Ключ APNs кладёт **пользователь** (содержимое не выводить):

```bash
sudo install -m 0600 -o root -g root AuthKey_<KEYID>.p8 /etc/credstore/hearth-apns.p8
```

`/etc/hearth/ntf.env`, права `0640 root:hearth`, ровно три строки; `APNS_KEY_FILE` сюда
**не** писать — его задаёт юнит:

```ini
APNS_KEY_ID=<Key ID>
APNS_TEAM_ID=5T376DA4G7
APNS_TOPIC=ru.myhearth.chat
```

`/etc/hearth/ntf-resolv.conf`, права `0644`, одна строка — DNS роутера, найденный на
шаге 3 (не брать `192.168.1.1` на веру):

```
nameserver <адрес>
```

Проверить путь к Apple от имени службы и подмену CA-файла, ещё до init:

```bash
sudo nft list counter inet hearth ntf_egress
sudo systemd-run --wait --pipe --quiet --uid=simplex-ntf -p BindReadOnlyPaths=/etc/hearth/ntf-resolv.conf:/etc/resolv.conf curl -sS -o /dev/null -w '%{http_code}\n' https://api.push.apple.com/
sudo nft list counter inet hearth ntf_egress
sudo nft list counter inet hearth egress_drop
sudo systemd-run --wait --pipe --quiet -p ProtectSystem=strict -p BindReadOnlyPaths=/etc/ssl/certs/ca-certificates.crt:/etc/ssl/cert.pem ls -l /etc/ssl/cert.pem
```

Ожидание: curl печатает HTTP-код (любой), `ntf_egress` вырос, `egress_drop` — нет;
последняя команда показывает файл. Если подмена `/etc/ssl/cert.pem` не монтируется —
убрать эту строку из `hearthd/deploy/systemd/ntf-server.service` и сделать на хосте
`ln -s /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem` (коммит с объяснением).

**СТОП 4** — отчёт и запрос «да» на init.

---

## 7. Init — необратимо

Отпечаток CA входит в адрес, который вшивается в iOS-сборку. Повторный init сменит его и
сломает пуши во всех установленных сборках. Скрипт второй раз не запустится — не обходить.

```bash
cd R/relays
sudo NODE_HOST=relay.myhearth.ru ./ntf/init-ntf.sh
sudo cat /etc/opt/simplex-ntf/address
sudo ./verify-ini-keys.sh /etc/opt/simplex-ntf/ntf-server.ini ntf/ntf-server.ini.example
```

Адрес сохранить.

**СТОП 5** — отчёт с адресом и запрос «да» на включение.

---

## 8. Включение

В боевой `/etc/hearth/hearthd.toml` **добавить** (файл не заменять):

- секцию `[ntf]` целиком из `R/hearthd/deploy/hearthd.toml`, с `enabled = true`;
- в `[egress]`: `"ntf-server"` в `relay_processes`, `"ntf_egress"` в `informational_counters`;
- в конец `[egress]`:

```toml
[[egress.process_allow]]
process = "ntf-server"
networks = ["17.0.0.0/8"]
ports = [443]
```

```bash
sudo hearthd --config /etc/hearth/hearthd.toml check
sudo systemctl enable --now ntf-server
sudo systemctl status ntf-server --no-pager
sudo journalctl -u ntf-server -b --no-pager -n 80
sudo systemctl enable --now ntf-db-dump.timer
sudo systemctl restart hearthd
```

```bash
HC status
HC mode show
```

Роутер: проброс `2053/tcp` → `192.168.1.72:2053` (`docs/runbook-router-udm.md`; сделать
так же, как сейчас сделан проброс 8443).

**Откат шага 8:** в `hearthd.toml` поставить `[ntf] enabled = false`, затем

```bash
sudo systemctl restart hearthd
sudo systemctl disable --now ntf-server ntf-db-dump.timer
```

Если узел ушёл в карантин: `HC mode show` → устранить причину → `HC mode clear`.

---

## 9. Проверка

На узле:

```bash
sudo nft list counter inet hearth egress_drop
sudo nft list counter inet hearth ntf_egress
sudo R/tests/acceptance/run-all.sh
```

С рабочей станции:

```bash
HC health
HC egress
```

Снаружи (VPS или телефон на мобильном интернете):

```bash
TARGET=relay.myhearth.ru NTF_PORT=2053 ./tests/acceptance/a04-port-scan.sh
openssl s_client -connect relay.myhearth.ru:2053 -brief </dev/null
```

Android: сообщение туда и обратно. Живой пуш на iPhone до iOS-сборки проверить нельзя —
записать как непроверенное.

---

## 10. Git и журнал

Исправления — коммитами в `ios-app-store-push`, push. Запись в конец
`docs/deploy-fels-2026-09-09.md` в стиле журнала: что сделано, что разошлось с этим
заданием и с `docs/runbook-ntf.md`, хеши бинарей.

## 11. Отчёт

1. Адрес `ntf://…@relay.myhearth.ru:2053`.
2. sha256 `ntf-server` и версия в манифесте; sha256 нового `hearthd`.
3. Ключ APNs: Topic Specific или командный; окружения.
4. Расхождения с заданием и runbook, список коммитов с исправлениями.
5. Результаты проверок и что осталось непроверенным.
