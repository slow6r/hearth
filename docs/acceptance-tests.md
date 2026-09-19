# Acceptance-тесты A1–A17

ТЗ §12. Автоматизируемая часть — в `tests/acceptance/`, остальное здесь как процедура.

```bash
sudo tests/acceptance/run-all.sh          # A1, A2, A3, A4, A12 — на узле
android/scripts/verify-apk.sh <apk>       # A5, A9 + отсутствие публичных адресов
```

Остальные требуют человека с телефоном.

---

## A1 — что слушает узел

**Изменено относительно ТЗ.** ТЗ требовало «релеи слушают только 10.66.10.10». Так не
получится: upstream документирует `[TRANSPORT] host` как «only used to print server
address on start» — сервер слушает все интерфейсы, и это нормально для публичного
релея. Ограничение адресов — задача фаервола, а не ini ([ADR 0007](adr/0007-public-relay-no-vpn.md)).

**Как:** `ss -tlnp` на узле.
**Ожидание:**
- релейные порты 8443, 5223, 443, 5443 слушаются (на любом адресе — ожидаемо);
- device API 7444 слушается, если `[device_api] enabled`;
- push-сервер 2053 слушается, если `[ntf] enabled` ([runbook-ntf.md](runbook-ntf.md));
- control-порты 5224, 5444 (и 5227 у push-сервера) — **только** на `127.0.0.1`;
- admin API 7443 — на LAN-адресе, **никогда** на `0.0.0.0`.

Включены ли необязательные сервисы, тест узнаёт сам из `/etc/hearth/hearthd.toml`.

Автоматизирован: `tests/acceptance/a01-listeners.sh`.

Дублируется в коде: `Config::validate` отвергает wildcard-бинд admin API и
control-порт вне loopback (тесты `admin_api_may_not_be_exposed`,
`rejects_non_loopback_control_port`).

---

## A2 — счётчик egress через 24 часа

**Как:** `nft list counters table inet hearth` (или `hearthctl egress`).
**Ожидание:** `egress_drop` = 0. Не «мало», а ноль.

На многоцелевом узле счётчик означает уже не «машина молчит», а «**релейный стек** не
пытался выйти в интернет» ([ADR 0008](adr/0008-multi-purpose-host.md)). Разрешённый
трафик приложений считается отдельно — `app_egress`, `turn_egress`, — и растёт, это норма.

Автоматизирован: `tests/acceptance/a02-egress-zero.sh` (проверяет и то, что счётчики
вообще читаются — слепой watchdog выглядит как чистый узел).

Если счётчик не ноль — это инцидент, а не шум. Разбор:

```bash
hearthctl egress --incidents        # куда именно пытались уйти
journalctl -k | grep hearth-egress-drop | tail -50
```

Типичные законные причины (все — повод поправить конфигурацию, а не игнорировать):
DHCP-клиент вместо статики, включённый `systemd-resolved`, окно обновления Debian,
запуск certbot для TURNS.

Пуши в Apple (`ntf_egress`, [ADR 0016](adr/0016-own-push-server.md)) — единственный
разрешённый выход самого релейного стека: пользователь `simplex-ntf`, только
`17.0.0.0/8:443`, и только на узле с push-сервером. Счётчик растёт с каждым пушем, это
норма. Если ntf-server пытается выйти куда-то ещё, это попадает в `egress_drop`, как у
любого релея, а сканер сокетов сверяет его соединения с `egress.process_allow`.

Медиатрафик coturn в этот счётчик **не попадает** — он разрешён явным правилом по
`skuid turnserver` и диапазону портов. Если он там появился, значит coturn работает не
от того пользователя или использует не тот диапазон: проверьте `min-port`/`max-port`
против `turn.relay_min_port`/`relay_max_port`.

`input_drop` на публичном узле растёт постоянно — это фоновые сканы интернета, норма.

---

## A3 — очередь без пароля не создаётся

**Как:** с устройства добавить сервер `smp://<fp>@<node.host>:5223` (без пароля) и
попытаться создать контакт.
**Ожидание:** релей отвергает создание очереди.

На публично доступном релее это единственный замок против посторонних — раньше вторым
был WireGuard. Пустой `create_password` = ваш сервер к услугам всего интернета.

Автоматизирован частично: `a03-queue-password.sh` проверяет, что `create_password`
задан в ini и что файл секрета существует и непустой. Полная проверка — с клиента.

---

## A4 — снаружи видно только нужные порты

**Как:** с машины **вне домашней сети** — VPS или телефон по мобильному интернету:

```bash
TARGET=<node.host> tests/acceptance/a04-port-scan.sh
```

**Ожидание:**

| Порт | Ожидание |
|---|---|
| 8443, 5223, 443, 5443/tcp | открыты — иначе клиенты не подключатся |
| 7444/tcp | открыт, если включён device API |
| 2053/tcp | открыт, если заведён push-сервер: `NTF_PORT=2053` при запуске теста |
| 3478 udp+tcp | открыт — иначе не соберётся звонок |
| **7443 (admin API)** | **закрыт.** Открытый = админка в интернете |
| **22 (ssh)** | **закрыт** |
| что-либо ещё | закрыто |

Это самый важный тест в новой модели: раньше от ошибки в пробросе защищал WG, теперь
не защищает ничто, кроме правильной настройки роутера.

Автоматизирован: `a04-port-scan.sh` (требует nmap).

---

## A5 — в APK нет Google/Firebase SDK

```bash
android/scripts/verify-apk.sh hearth-release.apk
```

Проверяет `com.google.android.gms`, `com.google.firebase`, Play Core, крэш-репортеры и
аналитику; заодно — отсутствие строк `*.simplex.im` и `stun.l.google.com`.

---

## A6 — экрана операторов нет

**Как:** в клиенте открыть настройки сети.
**Ожидание:** пункта «Операторы» / «Network operators» нет вовсе.

Регресс ловится при ребейзе: `android/patches/0002-hide-operators.md`.

---

## A7 — узел выключен 10 минут, сообщения не потеряны

**Как:**
1. `systemctl stop smp-server` (или выключить узел целиком);
2. с двух устройств отправить по несколько сообщений;
3. подождать 10 минут;
4. включить обратно.

**Ожидание:** все сообщения доставлены, порядок сохранён.

Это проверка store log (ТЗ §6.2) и заодно — принятого риска «один узел» (ТЗ §6.5).

---

## A8 — звонок идёт через наш TURN, а не через чужой

Самый важный функциональный тест: он одновременно проверяет, что звонки вообще работают,
и что они не утекли на публичные серверы.

**Как:** два устройства в **разных** сетях — идеально оба по мобильному интернету, у
разных операторов. Начать видеозвонок. В логе клиента посмотреть ICE-кандидаты.

**Ожидание:**
- звонок соединяется, звук и видео идут в обе стороны;
- среди relay-кандидатов — только `<node.host>`;
- **ни одного** `stun.simplex.im`, `turn.simplex.im`, `stun.l.google.com`.

**Если звонок соединился, но тишина** — почти наверняка не проброшен диапазон
49160–49200/udp. Сигнализация при этом выглядит здоровой, что и делает ошибку неприятной.

**Если в кандидатах публичные серверы** — значит клиент отбросил наш ICE-список целиком.
`parseRTCIceServers` возвращает `null` при одной некорректной записи и молча откатывается
на встроенные публичные серверы. Проверьте, что строки введены точно как выданы.

Дублируется в коде: bundle с публичным STUN или с credential, содержащим `/`, не проходит
валидацию ни в `hearthd` (`rejects_public_stun`, `credentials_are_always_uri_safe`), ни на
устройстве (`HearthBundleTest.rejectsAPublicStun`,
`rejectsCredentialsTheClientWouldDiscard`).

---

## A9 — данных приложения нет в бэкапах ОС

**Как:**
```bash
adb backup -f test.ab <applicationId>     # ожидаемо: пустой/отказ
```
Плюс проверить, что приложение не появляется в списке Google Backup на устройстве.

Автоматизировано в `verify-apk.sh`: `allowBackup=false` и `dataExtractionRules` в
манифесте собранного APK.

---

## A10 — скриншот и Recents чёрные

**Как:** попытаться сделать скриншот в приложении; свернуть и посмотреть превью в списке
недавних.
**Ожидание:** скриншот запрещён системой, превью — чёрное.

Это `FLAG_SECURE` без возможности выключить (`patches/0006-flag-secure.md`).

---

## A11 — восстановление из бэкапа на чистой VM

Полная процедура: [runbook-restore-drill.md](runbook-restore-drill.md). Квартально.

---

## A12 — sha256 бинарей против манифеста

```bash
hearthctl manifest verify
```

**Ожидание:** все `Ok`.

Проверка подмены (делать на тестовом стенде, не на боевом узле):

```bash
cp /usr/local/bin/smp-server /tmp/smp-server.bak
printf '\0' >> /usr/local/bin/smp-server        # порча бинаря
# ждём часовой цикл integrity или перезапускаем hearthd
hearthctl alerts --severity critical
systemctl is-active smp-server                   # должен быть остановлен
cp /tmp/smp-server.bak /usr/local/bin/smp-server
```

**Ожидание:** critical-алерт и остановленный релей. Fail-closed: узел, который не может
доказать, что запущено, не запускается.

Включённый релей, которого нет в манифесте, — такое же нарушение, как чужой хеш. Это про
push-сервер: его запись поставляется закомментированной и раскомментируется вместе с
`[ntf] enabled = true` ([runbook-ntf.md](runbook-ntf.md), шаг 3). Закомментированные
нули `a12-manifest.sh` не считает плейсхолдерами.

Автоматизирован: `a12-manifest.sh` (без порчи бинаря — только проверка совпадения).

---

## A13 — репетиция переезда

**До покупки mini-PC**, на тестовой VM: [runbook-migration.md](runbook-migration.md),
раздел «Репетиция».

**Ожидание:** клиент не заметил переезда.

---

## A15 — гейт режима узла

Проверяет главное обещание [ADR 0013](adr/0013-node-mode.md): пока узел в карантине,
переносе или обслуживании, релей не поднимается — ни надзором, ни `systemctl start`,
ни перезагрузкой. И обратное, не менее важное: у запрета есть выход, исполнимый на
самом узле.

### Неразрушающая половина (можно на боевом узле)

```bash
sudo tests/acceptance/a15-mode-gate.sh
```

Скрипт не трогает рабочие службы и не пишет в `/var/lib/hearth`: он гоняет гейт по
временным файлам режима и проверяет, что `ExecCondition` действительно подхвачен
systemd у smp, xftp, ntf и coturn.

**Ожидание:** нет файла → 0; `normal` → 0; `quarantine`/`migration`/`maintenance` → 1;
битый файл → 1; у каждого установленного юнита в `systemctl show -p ExecCondition`
виден `hearthctl mode gate`.

### Разрушающая половина (только на стенде или в окно обслуживания)

Это и есть настоящее доказательство: гейт проверяется не как функция, а как юнит.

```bash
# 1. Записать карантин руками (демон не нужен).
sudo install -m 0640 -o hearth -g hearth /dev/null /var/lib/hearth/node-mode.json
printf '{"mode":"quarantine","since":"%s","reason":"A15"}' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee /var/lib/hearth/node-mode.json >/dev/null

# 2. Попробовать поднять релей.
sudo systemctl start smp-server
systemctl is-active smp-server          # ждём inactive
journalctl -u smp-server -n 20 --no-pager

# 3. Перезагрузка — тот же ответ.
sudo reboot
systemctl is-active smp-server xftp-server coturn

# 4. Локальный выход при ЖИВОМ демоне: ничего не останавливая.
sudo systemctl is-active hearthd        # active
sudo hearthctl mode clear --local
sleep 20
systemctl is-active smp-server xftp-server coturn   # надзор поднял их сам

# 5. Локальный выход при МЁРТВОМ демоне: без hearthd и без сертификата.
sudo systemctl stop hearthd
printf '{"mode":"quarantine","since":"%s","reason":"A15"}' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | sudo tee /var/lib/hearth/node-mode.json >/dev/null
sudo hearthctl mode clear --local
sudo systemctl start smp-server xftp-server coturn hearthd

# 6. Битый файл режима: демон обязан СТАРТОВАТЬ, а не падать.
sudo systemctl stop hearthd
printf '{это не json' | sudo tee /var/lib/hearth/node-mode.json >/dev/null
sudo systemctl start hearthd
systemctl is-active hearthd             # active
hearthctl status                        # режим: карантин, причина — «не прочитан»
sudo hearthctl mode clear --local

# 7. Пропавший hearthctl: юнит пропущен БЕЗ строки `hearth:` в журнале.
sudo mv /usr/local/bin/hearthctl /root/hearthctl.bak
sudo systemctl start smp-server
journalctl -u smp-server -n 10 --no-pager
sudo mv /root/hearthctl.bak /usr/local/bin/hearthctl

# 8. Сломанный hearthd.toml: релеи обязаны подниматься, предупреждение — звучать.
sudo cp /etc/hearth/hearthd.toml /root/hearthd.toml.bak
printf 'это не toml\n' | sudo tee /etc/hearth/hearthd.toml >/dev/null
sudo hearthctl mode gate ; echo $?      # 0, плюс строка «ВНИМАНИЕ» в stderr
sudo systemctl start smp-server
systemctl is-active smp-server          # active
sudo cp /root/hearthd.toml.bak /etc/hearth/hearthd.toml

# 9. Провал preflight терминален: один отказ, а не петля из рестартов.
sudo mv /etc/hearth/manifest.toml /root/manifest.toml.bak
sudo systemctl restart hearthd || true
sleep 30
systemctl show hearthd -p NRestarts --value    # ждём, что число не растёт
journalctl -u hearthd -n 20 --no-pager
sudo mv /root/manifest.toml.bak /etc/hearth/manifest.toml
sudo hearthctl mode clear --local
sudo systemctl start hearthd
```

**Ожидание:**

| Шаг | Что обязано произойти |
|-----|------------------------|
| 2 | юнит **пропущен**, не failed: в журнале `Skipped due to 'exec-condition'`, рядом — строка `hearth: старт запрещён — режим: карантин … A15` и строка с локальным выходом |
| 2 | `smp-server` не слушает свой порт (`ss -lntp`), алертов о падении юнита нет |
| 3 | после перезагрузки релеи и coturn по-прежнему не поднялись |
| 4 | при живом демоне перезапускать его НЕ нужно: надзор перечитывает файл режима на каждом тике и поднимает релеи в пределах `check_interval_secs`. Сама команда печатает именно этот случай |
| 5 | `mode clear --local` отработал БЕЗ работающего hearthd и без сертификата, файл режима стал `normal` и принадлежит `hearth:hearth` (`stat -c %U:%G`), в `/var/lib/hearth/alerts.jsonl` появилась запись о локальном снятии, службы поднялись |
| 6 | hearthd **стартовал** на повреждённом файле режима, а не упал: в журнале «файл режима … не прочитан», режим — карантин с этой причиной. Раньше демон не стартовал вовсе, и узел оставался одновременно без релеев и без управления |
| 7 | юнит пропущен, но строки `hearth:` в журнале НЕТ — это признак неудачного запуска самого гейта (код 203), а не запрета режима. Лечение — runbook-node-mode.md §4 |
| 8 | нечитаемый `hearthd.toml` больше НЕ глушит все четыре юнита: гейт судит по `/var/lib/hearth/node-mode.json` и громко пишет, что путь взят по умолчанию. Ошибка администратора не должна стоить семье связи — runbook-node-mode.md §3 |
| 9 | hearthd остановился ОДИН раз с кодом 78 и не перезапускается (`NRestarts` не растёт), в журнале — причина и порядок действий. Раньше здесь была петля: каждые 5 с заново карантин, заново остановка релеев, и локальное снятие «держалось» ровно 5 секунд |

Дополнительно, если на узле нестандартный `paths.state_dir`: гейт обязан смотреть
именно в него (`sudo hearthctl mode gate ; echo $?` при записанном туда карантине даёт
1). Зашитый путь — это молчаливое разрешение старта в карантине.

**Отрицательная проверка установщика:** `deploy/install.sh` на машине без
`/usr/local/bin/hearthctl` и без собранного `target/.../hearthctl` обязан
ОСТАНОВИТЬСЯ с ошибкой на шаге **0**, то есть ДО того, как заменит хоть один файл на
узле. Проверяется так: убрать собранные бинарники и установленный hearthctl, запустить
скрипт, убедиться, что он вышел с ошибкой и что `/etc/systemd/system` не изменился
(`find /etc/systemd/system -newermt '-1 minute'` — пусто). Раньше проверка стояла на
шаге 6, и обрыв оставлял узел с новыми бинарниками, новыми конфигами и без
`daemon-reload`.

**Проверка ожидания монтирования:** если `paths.state_dir` на узле лежит на отдельном
разделе, drop-in гейта обязан его ждать:

```bash
systemctl show smp-server.service -p RequiresMountsFor --value   # ждём ваш state_dir
```

Без этого при неудачном порядке загрузки гейт не находит файла режима на ещё не
смонтированном разделе, считает узел обычным и МОЛЧА разрешает старт релея в карантине.

---

## A16 — работает тот код, который лежит в репозитории

Ответ на первый вопрос любого аудита. Раньше отвечать было нечем: `hearthd --version`
печатал `0.1.0`, одинаковое для любой сборки любого коммита за всю историю ветки.

```bash
sudo tests/acceptance/a16-provenance.sh
```

Скрипт сверяет четыре независимо полученных числа: sha256 файла на диске, sha256 из
журнала установки (`/var/lib/hearth/installed.build-info`), sha256 из манифеста и
`exe_sha256`, который назвал сам работающий процесс. Плюс коммит — он обязан быть один
во всех трёх местах, а `dirty` обязан быть `false`.

**Ручной шаг — под учётной записью auditor**, без sudo и без новых прав. Он и есть
смысл всей конструкции: связать процесс с файлом снаружи нельзя (`/proc/<pid>/exe`
требует ptrace, а ptrace — это заодно чтение памяти релеев, ТЗ §7.4), поэтому демон
называет свой хеш сам:

```bash
journalctl -u hearthd | grep exe_sha256 | tail -1
sha256sum /usr/local/bin/hearthd      # нужен ACL на один файл, выдаёт владелец
hearthd build-info                     # commit, tree_sha256
```

**Ожидание:** `exe_sha256` из журнала совпал с `sha256sum`, `commit` — 40 hex,
`dirty=false`. Расхождение `exe_sha256` с файлом означает, что работает не тот файл,
который лежит на диске, — это критическая находка, а не расхождение отчётности.

**Проверка выгрузки исходников:** `tree_sha256` из `hearthd build-info` обязан
совпасть с `tree_sha256` в манифесте выгрузки `/srv/hearth/src-<commit>/`. Совпали —
значит читаемые исходники и есть исходники работающего файла.

---

## A17 — авторизованный GET боевого узла без токена семьи

Проверяющий обязан скачать раздаваемую сборку своими руками и сверить байты.

```bash
# владелец:
hearthctl audit-token issue --ttl-hours 48 --max-uses 5 --scope updates \
    --write-token /home/auditor/audit.token
# аудитор:
curl -H "x-hearth-audit-token: $(cat audit.token)" https://<узел>:<порт>/updates/manifest.json
curl -H "x-hearth-audit-token: $(cat audit.token)" -O https://<узел>:<порт>/updates/<файл>.apk
sha256sum <файл>.apk    # против 14-updates.sha256 из выгрузки audit-dump.sh
```

**Ожидание:** три маршрута раздачи отвечают 200; `/turn-credentials` и
`/stickers/index.json` тем же токеном — 401; после отзыва (`audit-token revoke`) —
401 немедленно; в `hearthctl device list` не появилось ни одной новой записи.

---

## A18 — среда узла: автовход, sudo, swap, Secure Boot, версия coturn

Остальные проверки смотрят на узел изнутри контура hearth — файлы, юниты, счётчики — и
не видят среду, в которой он стоит. Аудит 18.09.2026 (п. 3.6) нашёл там то, чего не
поймал ни один тест: автовход GDM на учётку с `sudo NOPASSWD: ALL`, незашифрованный
swap-раздел и Secure Boot в Setup Mode.

```bash
sudo tests/acceptance/a18-host-env.sh
```

Скрипт **только смотрит**: он не правит ни файлов, ни служб, ни правил фаервола ни при
каком исходе. Что он проверяет и почему это важно:

| Проверка | Вердикт `!!` означает |
|---|---|
| Пользователь автовхода из `/etc/gdm3/daemon.conf` не состоит в `sudo` и не имеет `NOPASSWD` | Открытая сессия у телевизора равна root-шеллу: десять секунд у клавиатуры — ключ CA релея |
| Владелец графической сессии (`loginctl`) — тот же критерий | То же, но по факту, а не по конфигу |
| Ни у одного интерактивного uid ≥ 1000 нет `NOPASSWD` | Пароль как барьер отменён. Демону `sudo` не нужен вовсе — `hearthd` ходит через polkit |
| Каждое устройство swap — zram или поверх `dm-crypt` | На диске лежат копии памяти `hearthd`: пароли создания очередей и `static-auth-secret` |
| `sleep/suspend/hibernate/hybrid-sleep` замаскированы | Сон останавливает доставку, а гибернация несовместима со случайным ключом swap |
| Кандидат `coturn` совпадает с установленным | Вышедшее обновление пакета на публичном порту 3478 не поставлено (ТЗ §1.4: ≤ 7 дней) |

Справочно (печатается, но не валит тест): состояние Secure Boot и Setup Mode, наличие
TPM, наличие разделов `crypto_LUKS`. Все три — предмет принятых решений
([ADR 0009](adr/0009-no-full-disk-encryption.md)), а не дефектов.

**Ожидание:** на приведённом к документам узле — «Среда узла соответствует записанным
решениям». Сегодня на `fels` тест красный, и это правда, а не поломка теста: что с ней
делать и в каком порядке — [runbook-host-hardening.md](runbook-host-hardening.md).

---

## Сводка автоматизации

| Тест | Автоматизирован | Где |
|---|---|---|
| A1 | да | `tests/acceptance/a01-listeners.sh` + `Config::validate` |
| A2 | да | `a02-egress-zero.sh` + модуль `egress` |
| A3 | частично | `a03-queue-password.sh`; полная — с клиента |
| A4 | да | `a04-port-scan.sh` |
| A5 | да | `android/scripts/verify-apk.sh` |
| A6 | нет | ручная проверка UI |
| A7 | нет | ручная, с двух устройств |
| A8 | частично | валидация bundle с обеих сторон; кандидаты — вручную |
| A9 | да | `verify-apk.sh` |
| A10 | нет | ручная проверка |
| A11 | процедура | `runbook-restore-drill.md`, квартально |
| A12 | да | `a12-manifest.sh` + модуль `integrity` |
| A13 | процедура | `runbook-migration.md` |
| A15 | да | `a15-mode-gate.sh` + модуль `model::mode`; разрушающая половина — вручную |
| A16 | да | `a16-provenance.sh` + `tests/build_info.rs` |
| A17 | частично | модульные тесты `deviceapi`/`audit_token`; сеть — вручную |
| A18 | да | `a18-host-env.sh` — только чтение; BIOS и Secure Boot справочно, правится руками |
