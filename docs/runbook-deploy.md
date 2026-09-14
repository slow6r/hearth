# Runbook: развёртывание узла

Домашнее железо, релеи доступны из интернета ([ADR 0007](adr/0007-public-relay-no-vpn.md)).
На фазе 0 это существующий ПК, на фазе 1 — mini-PC; переезд между ними не меняет адрес
релея ([runbook-migration.md](runbook-migration.md)).

**Время:** 2–4 часа, из них половина — установка Debian.

---

## 0. Что решить до начала

### Публичное имя (`node.host`)

Это самое важное решение: имя попадает в адрес каждого клиента и **пережить его смену
нельзя без ручной перенастройки всех контактов у всех** ([runbook-rotate-address.md](runbook-rotate-address.md)).

| Вариант | Когда подходит |
|---|---|
| Домен + динамический DNS | почти всегда. Домашний IP меняется — имя нет |
| Голый статический IP | только если провайдер даёт статику по договору |
| Домен + Let's Encrypt | нужен, если хотите TURNS на 443 для звонков из ограниченных сетей |

DDNS обновляет **роутер**, а не узел: у узла нет исходящего доступа, и так и должно
остаться.

### ПК целиком или VM

Рекомендация — bare metal. Мессенджер, который замолкает, когда владелец закрыл ноутбук,
задачу не решает. Если ПК нужен под другое — VM с автозапуском и выключенными
sleep/hibernate на хосте.

---

## 1. Debian minimal

- Debian stable, без графики.
- **LUKS на весь диск.** Ключ — на USB-токене или TPM с PIN. Без диска содержимое
  бесполезно; это защита от кражи железа.
- Отдельный раздел под `/var` желателен: store log растёт.

```bash
# Резолвера на узле нет: он ничего не резолвит, значит нечего подменять
systemctl disable --now systemd-resolved
: > /etc/resolv.conf

# Сон убивает доставку
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# У узла нет egress — автообновления не сработают, а перезагрузка некстати сработает
systemctl disable --now unattended-upgrades 2>/dev/null || true
```

## 2. Сеть

Узлу нужен **фиксированный адрес в LAN** (для admin API и проброса портов) — статикой
или DHCP-резервацией на роутере.

`/etc/systemd/network/10-hearth.network`:

```ini
[Match]
Name=enp*

[Network]
Address=192.168.1.10/24
Gateway=192.168.1.1
# DNS не указываем: резолвер выключен
# Время — с роутера: внешний NTP недоступен по дизайну, а от часов зависят
# TURN-креды и сертификаты admin API
NTP=192.168.1.1
```

```bash
systemctl enable --now systemd-networkd
timedatectl set-ntp true
```

### Проброс портов на роутере

| Порт | Протокол | Зачем |
|---|---|---|
| 8443 | TCP | SMP-релей: порт в адресах клиентов ([почему не 443](deploy-fels-2026-09-09.md)) |
| 5223 | TCP | SMP-релей, прежние адреса |
| 443 | TCP | SMP-релей, запасной вход из ограниченных сетей |
| 5443 | TCP | XFTP (файлы) |
| 3478 | UDP + TCP | STUN/TURN, сигнализация звонка |
| 49160–49200 | UDP |TURN-медиа. **Без этого звонок соединится и будет молчать** |
| 7444 | TCP | Device API — если `[device_api] enabled` |
| 2053 | TCP | Push-сервер для iOS — только если он заведён ([runbook-ntf.md](runbook-ntf.md)) |

Порты 7443 (admin API) и 22 (ssh) **не пробрасывать**.

Если узел за NAT, в `/etc/hearth/templates/turnserver.conf.tmpl` добавьте
`external-ip=<публичный>/<локальный>` — иначе coturn объявит недостижимый ICE-кандидат.

## 3. Firewall — до релеев, а не после

```bash
apt install nftables
install -d -m 0755 /etc/hearth/nftables
install -m 0644 hearthd/deploy/nftables/hearth.nft /etc/hearth/nftables/hearth.nft
$EDITOR /etc/hearth/nftables/hearth.nft     # set lan_nets под вашу сеть
nft -c -f /etc/hearth/nftables/hearth.nft   # проверка синтаксиса
nft -f /etc/hearth/nftables/hearth.nft

echo 'include "/etc/hearth/nftables/hearth.nft"' >> /etc/nftables.conf
systemctl enable --now nftables
nft list counters table inet hearth          # egress_drop = 0
```

Порядок важен: правила загружаются **до** первого запуска релея.

## 4. Бинари релеев

Скачиваются и проверяются GPG **на другой машине** (у узла нет интернета), переносятся
USB. Процедура — [relays/README.md](../relays/README.md) §1.

```bash
install -m 0755 smp-server  /usr/local/bin/smp-server
install -m 0755 xftp-server /usr/local/bin/xftp-server
```

## 5. hearthd и инициализация

```bash
# на машине разработки
cargo build --release --target x86_64-unknown-linux-musl
# на узле
sudo ./hearthd/deploy/install.sh
$EDITOR /etc/hearth/hearthd.toml     # node.host, lan_networks, api.listen, recipients
```

Дальше по подсказкам скрипта:

```bash
# 1. Инициализация релеев — ОДИН РАЗ за жизнь узла
cd relays && ./smp/init-smp.sh && ./xftp/init-xftp.sh
./verify-ini-keys.sh /etc/opt/simplex/smp-server.ini smp/smp-server.ini.example

# 2. Пиннинг хешей
hearthctl manifest pin --name smp-server  --version <tag>
hearthctl manifest pin --name xftp-server --version <tag>
hearthctl manifest pin --name hearthd     --version 0.1.0

# 3. Admin PKI
hearthd ca init
hearthd ca issue owner
#    owner.key перенести на рабочую станцию и удалить с узла

# 4. Бэкап: age-ключ генерируется НЕ на узле, в конфиг идёт только публичная часть
$EDITOR /etc/hearth/hearthd.toml      # backup.recipients

# 5. TURN
apt install coturn
hearthctl rotate turn-secret

# 6. Старт
systemctl enable --now smp-server xftp-server coturn hearthd
hearthctl health
```

## 6. Проверка

```bash
sudo tests/acceptance/run-all.sh
```

Плюс снаружи (с телефона по мобильной сети, не из дома):

```bash
nc -vz <node.host> 5223      # открыт
nc -vz <node.host> 7443      # ДОЛЖЕН быть закрыт
```

Через сутки повторить A2: `egress_drop` обязан остаться нулём.

## 7. Первое устройство и звонок

[runbook-device-add.md](runbook-device-add.md). Обязательно проверьте **звонок между
двумя устройствами в разных сетях** (например, оба по мобильному интернету) — это
единственный способ убедиться, что TURN-медиа реально ходит.

---

## Что легко сделать неправильно

| Ошибка | Чем аукнется |
|---|---|
| Не пробросили 49160–49200/udp | Звонок соединяется и молчит. Сигнализация при этом выглядит здоровой |
| Узел за NAT без `external-ip` в coturn | То же самое: недостижимый ICE-кандидат |
| Пробросили 7443 или 22 наружу | Админка и ssh в интернете. A4 это ловит |
| `create_password` пустой | Любой желающий создаёт очереди на вашем релее. На публичном сервере это единственный замок |
| Порт 443 без `CAP_NET_BIND_SERVICE` | Релей не стартует. В поставляемом юните capability есть |
| Повторный `smp-server init` | Новый отпечаток CA → новый адрес → перенастройка всех контактов вручную |
| age-ключ сгенерирован на узле | Компрометация узла = компрометация всех бэкапов |
| `owner.key` остался на узле | Один взлом даёт и узел, и права админа |
| Файлы вне каталогов `backup.paths` | Переезд на mini-PC потеряет их |

---

## Push-сервер для iOS (по желанию)

Нужен только узлу, у которого есть пользователи iOS-приложения Hearth: без него iPhone
узнаёт о сообщении, только открыв приложение. Заводится поверх готового узла и
добавляет PostgreSQL, собранный из исходников `ntf-server`, порт 2053 и первый
разрешённый выход релейного стека наружу — к Apple. Решение и цена —
[ADR 0016](adr/0016-own-push-server.md), процедура — [runbook-ntf.md](runbook-ntf.md).
