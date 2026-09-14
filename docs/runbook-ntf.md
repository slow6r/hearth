# Runbook: push-сервер для iOS-приложения

Решение и его цена — [ADR 0016](adr/0016-own-push-server.md). Здесь — только как это
завести, проверить, обслуживать и переносить.

**Кому нужен.** Только узлу, у которого есть пользователи iOS-приложения Hearth. Без
push-сервера iPhone узнаёт о сообщении, лишь когда приложение открыто. Android пушей не
использует вовсе, узлу без iOS этот runbook не нужен.

**Что появляется на узле** — сразу, чтобы решение принималось с открытыми глазами:

| Что | Где | Почему это не мелочь |
|---|---|---|
| `ntf-server` | simplexmq v7.0.1 + один патч | первый собранный нами из исходников бинарь upstream |
| PostgreSQL | локальный сокет, без сети | в v7.0.1 у ntf-server нет другого хранилища |
| порт 2053/tcp | из интернета | новая публичная поверхность |
| выход к `17.0.0.0/8:443` | пользователь `simplex-ntf` | **первое исключение из egress релейного стека** |
| ключ APNs | `/etc/credstore/hearth-apns.p8` | подписывает пуши от имени команды Apple |

---

## 1. Apple: ключ APNs

developer.apple.com → Certificates, Identifiers & Profiles → **Keys** → «+», сервис
**Apple Push Notifications service (APNs)**.

**Ограничьте ключ, если портал это позволяет.** Там, где при создании ключа есть выбор
окружения (Sandbox / Production) и области (Team Scoped / **Topic Specific**), берите:

- Topic Specific → `ru.myhearth.chat`;
- Production — для сборок из App Store и TestFlight. Отладочные сборки из Xcode ходят в
  sandbox и с таким ключом пушей не получат, это ожидаемо.

Почему это важно: ключ лежит на машине, которая слушает интернет. **Командный ключ
без ограничений позволяет слать пуши в любое приложение команды 5T376DA4G7**, а не только
в Hearth. Ограниченный ключ сужает ущерб от кражи узла до одного приложения. Если
выбора в портале нет, ключ будет командным — это надо знать и держать в голове при
любом инциденте с узлом.

Файл `AuthKey_<KEYID>.p8` скачивается **один раз**. Сразу:

- копия офлайн, рядом с ключами подписи (не в репозиторий: `keys/` принимает только
  публичное);
- записать Key ID (10 знаков, он же в имени файла).

## 2. Бинарь

На рабочей станции с Docker, не на узле:

```bash
relays/ntf/build-ntf-server.sh
```

Скрипт сверяет коммит тега, накладывает `relays/ntf/patches/`, собирает в закреплённом
образе и печатает sha256 и паспорт сборки. Первая сборка — часы.

Перенос на узел — USB, как у релеев. На узле:

```bash
apt install postgresql libpq5 libgmp10 libnuma1    # точный список — dist/ntf-server.ldd
install -m 0755 ntf-server /usr/local/bin/ntf-server
```

## 3. Манифест

В `/etc/hearth/manifest.toml` раскомментировать блок `ntf-server` и запинить:

```bash
hearthctl manifest pin --name ntf-server --version v7.0.1+hearth.1
```

Не пропускать: как только в `hearthd.toml` включён `[ntf]`, hearthd считает релей без
записи в манифесте нарушением целостности и **останавливает все релеи** (карантин).

## 4. Ключ, окружение, резолвер

```bash
install -d -m 0700 /etc/credstore
install -m 0600 -o root -g root AuthKey_<KEYID>.p8 /etc/credstore/hearth-apns.p8
```

Ключ получает только служба и только через `LoadCredential`: ни `simplex-ntf`, ни
hearthd прочитать его на диске не могут, и в ночной бэкап он не попадает.

`/etc/hearth/ntf.env` (0640 root:hearth):

```ini
APNS_KEY_ID=<Key ID из шага 1>
APNS_TEAM_ID=5T376DA4G7
APNS_TOPIC=ru.myhearth.chat
```

`APNS_KEY_FILE` сюда **не** писать: его задаёт юнит, и значение из этого файла его
перекрыло бы.

`/etc/hearth/ntf-resolv.conf` (0644) — резолвер только для этой службы:

```
nameserver 192.168.1.1
```

Узел по-прежнему ничего не резолвит; `api.push.apple.com` — имя, и без этого файла ни
один пуш не уйдёт. `/etc/hosts` не подменяется, поэтому `relay.<host>` для ntf-server
остаётся LAN-адресом, как для самого релея.

## 5. Инициализация

```bash
cd relays
NODE_HOST=relay.myhearth.ru ./ntf/init-ntf.sh
./verify-ini-keys.sh /etc/opt/simplex-ntf/ntf-server.ini ntf/ntf-server.ini.example
```

Скрипт заводит роль, базу и схему в PostgreSQL, запускает `ntf-server init`, правит ini
(порт 2053, control port 5227 с паролями) и печатает адрес:

```
ntf://<отпечаток>@relay.myhearth.ru:2053
```

**Этот адрес вшивается в сборку iOS-приложения.** Он же лежит в
`/etc/opt/simplex-ntf/address`. Повторный init меняет отпечаток и ломает пуши у всех
установленных сборок, поэтому скрипт откажется запускаться второй раз.

## 6. hearthd, фаервол, роутер

`/etc/hearth/hearthd.toml`:

```toml
[ntf]
enabled = true
# остальное — как в эталоне hearthd/deploy/hearthd.toml

[egress]
relay_processes = ["smp-server", "xftp-server", "ntf-server"]
informational_counters = ["app_egress", "turn_egress", "ntf_egress"]

[[egress.process_allow]]
process = "ntf-server"
networks = ["17.0.0.0/8"]
ports = [443]
```

Без `ntf-server` в `relay_processes` конфиг не пройдёт проверку: релей, за сокетами
которого никто не смотрит, — слепое пятно. Без `process_allow` сканер сокетов объявит
инцидентом каждое соединение с Apple.

```bash
hearthd --config /etc/hearth/hearthd.toml check
nft -c -f /etc/hearth/nftables/hearth.nft && nft -f /etc/hearth/nftables/hearth.nft
```

Роутер: проброс **2053/tcp** на узел (runbook-router-udm.md).

```bash
systemctl enable --now ntf-server ntf-db-dump.timer
systemctl restart hearthd
hearthctl health
```

## 7. Проверка

| Что | Как | Ожидание |
|---|---|---|
| служба живая | `hearthctl health` | `ntf` — ok, control port отвечает |
| APNs доступен | `journalctl -u ntf-server -b` | нет ошибок TLS/JWT к `api.push.apple.com` |
| телефон зарегистрировался | тот же журнал после включения уведомлений в приложении | регистрация токена устройства |
| выход только к Apple | `nft list counter inet hearth ntf_egress` | растёт при пушах |
| больше никуда | `nft list counter inet hearth egress_drop` | **0** |
| сокеты | `hearthctl egress` | нет foreign sockets |
| порт снаружи | `TARGET=<host> NTF_PORT=2053 tests/acceptance/a04-port-scan.sh` | 2053 открыт |
| на узле | `sudo tests/acceptance/run-all.sh` | A1 видит 2053 и 5227, A14 — права |

Живой тест: заблокировать iPhone, написать ему с другого устройства — уведомление
приходит за секунды.

Если `egress_drop` вырос после включения — посмотреть адресатов
(`hearthctl egress --incidents`). Самые вероятные причины: ntf-server пытается дойти до
SMP-сервера, которого нет в `/etc/hosts` (чужой релей у контакта), или APNs ответил
адресом вне `17.0.0.0/8`. Первое — находка, второе — повод пересмотреть правило, а не
расширять его вслепую.

## 8. Ротация и отзыв ключа

Плановая замена или подозрение на утечку — одинаково:

1. Создать новый ключ (шаг 1), положить офлайн-копию.
2. `install -m 0600 -o root -g root AuthKey_<NEW>.p8 /etc/credstore/hearth-apns.p8`
3. `APNS_KEY_ID=<NEW>` в `/etc/hearth/ntf.env`.
4. `systemctl restart ntf-server`, проверить журнал и живой пуш.
5. **Отозвать старый ключ в портале Apple.** До отзыва украденный ключ работает, где бы
   он ни лежал.

Узел украден или взломан — сначала пункт 5, потом всё остальное: командный ключ на
чужой машине опаснее, чем пропавшие пуши.

## 9. Перенос узла

`hearthctl migrate export` останавливает и ntf-server. В архиве:
`/etc/opt/simplex-ntf` (CA — адрес не меняется) и `/var/opt/simplex-ntf` с ночным
дампом базы. **Не в архиве:** ключ APNs и живая база.

На старом узле, после export (ntf-server уже стоит):

```bash
runuser -u simplex-ntf -- pg_dump --format=custom \
    --file=/var/opt/simplex-ntf/ntf-db.dump ntf_server_store
```

и перенести этот файл вместе с архивом. На новом узле после `migrate import`:

```bash
apt install postgresql
runuser -u postgres -- psql -c 'CREATE ROLE "simplex-ntf" LOGIN'
runuser -u postgres -- psql -c 'CREATE DATABASE ntf_server_store OWNER "simplex-ntf"'
runuser -u simplex-ntf -- pg_restore --dbname=ntf_server_store /var/opt/simplex-ntf/ntf-db.dump
```

Ключ APNs — из офлайн-копии (шаг 4). `init-ntf.sh` на новом узле **не запускать**.

Если база потерялась совсем, адрес push-сервера сохраняется (его держит CA), но сервер
забывает токены устройств. Сам ли клиент перерегистрирует токен в этом случае — не
проверено; закладывайтесь на то, что на телефонах придётся выключить и снова включить
уведомления.

## Что легко сделать неправильно

| Ошибка | Чем аукнется |
|---|---|
| `nft -f` до создания `simplex-ntf` | не загрузится **весь** ruleset, а с ним не стартуют релеи |
| hearthd.service обновили без install.sh | hearthd не стартует: нет группы `simplex-ntf` |
| `[ntf] enabled = true` без записи в манифесте | карантин узла, все релеи остановлены |
| нет `/etc/hearth/ntf-resolv.conf` | служба работает, пуши молча не уходят |
| ключ Sandbox при сборке из App Store | то же самое: APNs отвергает токены |
| `APNS_KEY_FILE` в ntf.env | служба не находит ключ |
| повторный `init-ntf.sh` | новый отпечаток, пуши сломаны у всех сборок |
| командный ключ без офлайн-копии | ротация превращается в выпуск нового ключа под давлением |
