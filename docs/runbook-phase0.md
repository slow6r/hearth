# Runbook: фаза 0 — узел на существующем ПК

Соответствует ТЗ §10.1, §11. Цель — работающий контур до покупки mini-PC, устроенный так,
чтобы переезд (§10.2) был вечерней задачей, а не проектом.

**Время:** 2–4 часа, из них половина — ожидание установки Debian.

---

## 0. Решение, которое нужно принять до начала

ТЗ §15.1: ПК целиком под Debian или VM?

| | Вариант A: bare metal | Вариант B: VM |
|---|---|---|
| Контроль egress | полный | полный внутри VM, но хост остаётся вне контура |
| LUKS | весь диск | диск VM; хост может быть незашифрован |
| Sleep/перезагрузки | под контролем | зависят от хоста — **главный риск** (ТЗ §14) |
| ПК можно использовать | нет | да |

**Рекомендация: вариант A.** Причина в ТЗ §14: «ПК используется как рабочая машина →
перезагрузки, sleep» — риск с вероятностью «высокая». Мессенджер, который замолкает,
когда владелец закрыл ноутбук, не выполняет свою задачу.

Если всё же вариант B: bridged NIC в отдельный VLAN, автозапуск VM при старте хоста,
на хосте выключены sleep/hibernate.

---

## 1. Debian minimal

- Debian stable, установка без окружения рабочего стола, только SSH server и утилиты.
- **LUKS на весь диск.** Ключ — на USB-токене или TPM с PIN (ТЗ §11).
  Без диска содержимое бесполезно — это и есть защита от кражи железа (ТЗ §3.1).
- Разметка: отдельный раздел под `/var` желателен — store log растёт.

Сразу после установки:

```bash
# Резолвера на узле нет (ТЗ §5.2): перехватывать нечего
systemctl disable --now systemd-resolved
: > /etc/resolv.conf
chattr +i /etc/resolv.conf          # чтобы DHCP-клиент не вернул сервера обратно

# Сон убивает доставку сообщений
systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# У узла нет egress — автообновления всё равно не сработают, а перезапуск некстати сработает
systemctl disable --now unattended-upgrades 2>/dev/null || true
```

## 2. Сеть — статикой, не DHCP

Резервация на UDM Pro остаётся (она нужна для переезда), но **адрес настраивается
статически**. Причина: DHCP-клиенту нужен broadcast на `255.255.255.255`, а `output`
policy его дропает — и `egress_drop` перестанет быть чистым нулём.

`/etc/systemd/network/10-hearth.network`:

```ini
[Match]
Name=enp*

[Network]
Address=10.66.10.10/24
Gateway=10.66.0.1
# DNS не указываем: его нет
# Время берём с роутера — он внутри home_networks
NTP=10.66.0.1
```

```bash
systemctl enable --now systemd-networkd
timedatectl set-ntp true            # источник — 10.66.0.1, внутри контура
```

**Про время.** Оно важно: от него зависят срок действия TURN-кредов и сертификатов
admin API. Внешние NTP-серверы недоступны по дизайну, поэтому источник — роутер.

## 3. Firewall (ТЗ §5.3) — до релеев, а не после

```bash
apt install nftables
install -d -m 0755 /etc/hearth/nftables
install -m 0644 hearthd/deploy/nftables/hearth.nft /etc/hearth/nftables/hearth.nft
nft -c -f /etc/hearth/nftables/hearth.nft        # проверка синтаксиса
nft -f /etc/hearth/nftables/hearth.nft

echo 'include "/etc/hearth/nftables/hearth.nft"' >> /etc/nftables.conf
systemctl enable --now nftables

nft list counters table inet hearth               # egress_drop = 0
```

Порядок важен: правила загружаются **до** первого запуска релея, чтобы у него не было ни
одного окна, когда egress разрешён.

## 4. Бинари релеев

Скачиваются и проверяются **на другой машине** (у узла нет интернета), переносятся USB.
Процедура с GPG-проверкой — [relays/README.md](../relays/README.md) §1.

```bash
install -m 0755 smp-server  /usr/local/bin/smp-server
install -m 0755 xftp-server /usr/local/bin/xftp-server
```

## 5. hearthd

```bash
# на машине разработки
cargo build --release --target x86_64-unknown-linux-musl
# на узле
sudo ./hearthd/deploy/install.sh
```

`install.sh` создаёт пользователей и каталоги, ставит юниты, и **останавливается** перед
шагами, требующими решений. Дальше по его подсказкам:

```bash
# 1. Инициализация релеев (один раз за жизнь узла!)
cd relays && ./smp/init-smp.sh && ./xftp/init-xftp.sh
./verify-ini-keys.sh /etc/opt/simplex/smp-server.ini smp/smp-server.ini.example

# 2. Пиннинг хешей (ТЗ §6.1)
hearthctl manifest pin --name smp-server  --version <tag>
hearthctl manifest pin --name xftp-server --version <tag>
hearthctl manifest pin --name hearthd     --version 0.1.0

# 3. Admin PKI
hearthd ca init
hearthd ca issue owner
#    owner.key перенести на рабочую станцию и удалить с узла

# 4. Бэкап: свой age-ключ
#    ключ генерируется НЕ на узле (age-keygen на доверенной машине),
#    в /etc/hearth/hearthd.toml прописывается только публичная часть
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
tests/acceptance/run-all.sh           # A1, A2, A3, A4, A12
```

Через сутки повторить A2: `egress_drop` обязан остаться нулём.

## 7. Первое устройство

[runbook-device-add.md](runbook-device-add.md).

---

## Что легко сделать неправильно

| Ошибка | Чем аукнется |
|---|---|
| Релей на хостовой Windows/Docker Desktop | Нет контроля egress, нет LUKS, sleep убивает доставку (ТЗ §10.1 прямо запрещает) |
| Файлы вне трёх каталогов §10.1 | Переезд станет ручным и потеряет что-нибудь |
| Повторный `smp-server init` | Новый отпечаток CA → новый адрес → перенастройка всех контактов вручную |
| age-ключ сгенерирован на узле | Компрометация узла = компрометация всех бэкапов |
| `owner.key` остался на узле | Один взлом даёт и узел, и права админа |
| DHCP вместо статики | `egress_drop` растёт от broadcast — сигнал утечки перестаёт быть чистым |
