# Мониторинг узла

Три слоя, и один из них уже работает.

| Слой | Кто следит | Куда шлёт |
|---|---|---|
| Мессенджер: юниты, порты, egress, хеши бинарей, бэкапы | **`hearthd`** — уже есть | Gotify + `hearthctl status` |
| Железо и ОС: CPU, RAM, диск, температура, SMART | node_exporter + Prometheus | Alertmanager → Gotify |
| Внутренности релеев: очереди, поток сообщений | **сами релеи** пишут метрики в файл | тот же Prometheus |

Ставить второй и третий слой имеет смысл, если на машине живёт что-то ещё, кроме
мессенджера. Если она однозадачная — `hearthd` покрывает всё нужное, и Prometheus
можно не разворачивать.

---

## Релеи умеют Prometheus сами

Это не наша доработка — это есть в upstream. В ini включается одной строкой:

```ini
[STORE_LOG]
prometheus_interval = 60
```

Метрики пишутся **в файл**, не по HTTP:

- `/var/opt/simplex/smp-server-metrics.txt`
- `/var/opt/simplex-xftp/xftp-server-metrics.txt`

Забираются штатным textfile-коллектором `node_exporter` — он подхватывает всё с
расширением `.prom` из указанного каталога:

```bash
install -d -o node_exporter -g node_exporter /var/lib/node_exporter/textfile
ln -sf /var/opt/simplex/smp-server-metrics.txt \
       /var/lib/node_exporter/textfile/smp-server.prom
ln -sf /var/opt/simplex-xftp/xftp-server-metrics.txt \
       /var/lib/node_exporter/textfile/xftp-server.prom
```

`node_exporter` должен иметь право читать эти файлы — добавьте его в группу `simplex`
либо ослабьте права на сами файлы метрик (в них нет ничего чувствительного: счётчики,
без адресов клиентов).

## Установка

```bash
apt install prometheus prometheus-node-exporter prometheus-alertmanager grafana
```

Файлы отсюда:

| Файл | Куда |
|---|---|
| `prometheus.yml` | `/etc/prometheus/prometheus.yml` |
| `alerts.yml` | `/etc/prometheus/alerts.yml` |
| `node-exporter-override.conf` | `/etc/systemd/system/prometheus-node-exporter.service.d/hearth.conf` |

После этого — правило фаервола на доступ к Grafana только из LAN (см. ниже) и
`systemctl enable --now prometheus prometheus-node-exporter grafana-server`.

## Доступ — только из LAN

Grafana и Prometheus **не должны торчать в интернет**. Это тот же принцип, что и с
admin API: мессенджер публичен, управление — нет.

В `/etc/hearth/nftables/hearth.nft`, в цепочку `input`, рядом с правилом для 7443:

```nft
ip saddr @lan_nets tcp dport { 3000, 9090, 9093 } counter name admin_in accept
```

3000 — Grafana, 9090 — Prometheus, 9093 — Alertmanager. Наружу их не пробрасывать
на роутере. Проверяется тестом A4.

Дополнительно стоит забиндить сами сервисы на LAN-адрес, а не на wildcard:
в `/etc/default/prometheus` и `/etc/grafana/grafana.ini` укажите конкретный адрес.

## Алерты — в тот же Gotify

`hearthd` уже шлёт туда критические события мессенджера. Alertmanager направляется
туда же, чтобы канал был один:

```yaml
# /etc/prometheus/alertmanager.yml
receivers:
  - name: gotify
    webhook_configs:
      - url: 'http://192.168.1.1:8088/message?token=ВАШ_ТОКЕН'
```

Gotify держите **не на этой машине**: уведомление о том, что сервер умер, не должно
жить на умершем сервере. В конфиге `hearthd` он уже указан на роутере.

## Что это добавляет к egress

Prometheus и node_exporter работают локально и наружу не ходят. Но если вы дадите им
скрейпить что-то за пределами LAN, добавьте пользователя `prometheus` в правило
`app_egress` в `hearth.nft` — иначе трафик попадёт в `egress_drop` и поднимет ложный
инцидент.

---

## Как это развёрнуто на fels (2026-09-09)

Отличия от процедуры выше — не по вкусу, а потому что иначе не работает.

**Grafana не ставилась.** Пакет биндится на `127.0.0.1:3000`, а там Next.js сайта
you-can-do.ru. Prometheus умеет строить графики сам; отдельный порт под Grafana
(3001) можно завести позже, если понадобится.

**Правила про `/` дополнены группой `hearth-data-partitions`.** На этой машине данные
мессенджера живут не на корне: `/var/opt/simplex`, `/var/opt/simplex-xftp` и
`/var/opt/hearth` — bind-mount'ы на `/srv` (425 GiB), а `/var` — отдельный раздел на
12 GiB. Store log может залить любой из них, а `/` при этом останется здоровым, и
исходные правила не сработают.

**Gotify нет — алерты идут в локальный приёмник.** Роутер на 8088 не отвечает.
Alertmanager, настроенный на мёртвый эндпоинт, даёт ошибку доставки на каждый алерт,
и через неделю на алерты перестают смотреть. Вместо этого:

```
Alertmanager --webhook--> 127.0.0.1:9099 (hearth-alert-sink)
                              |
                              +--> journald
                              +--> /var/log/hearth-alerts.log
                              +--> hearth-beep (wall) для severity=critical
```

Туда же пишет `alerts.beeper` самого `hearthd`, так что смотреть надо в одно место.

Файлы: `alertmanager.yml`, `hearth-alert-sink`, `hearth-alert-sink.service` здесь же.

**Это временное решение.** Уведомление о том, что сервер умер, не должно жить на
умершем сервере. Gotify на отдельной машине остаётся открытым пунктом; когда он
появится, меняется один `url` в `alertmanager.yml` и возвращается секция
`[alerts.gotify]` в `hearthd.toml`.

### Привязка к адресам

| Сервис | Адрес | Почему так |
|---|---|---|
| Prometheus | `192.168.1.72:9090` | UI нужен из LAN |
| Alertmanager | `192.168.1.72:9093` | то же |
| node_exporter | `127.0.0.1:9100` | его читает только Prometheus с этой же машины |
| hearth-alert-sink | `127.0.0.1:9099` | принимает только от Alertmanager |

Порты 9090/9093/9100 открыты в `hearth.nft` только для `@lan_nets` и **не
пробрасываются** на роутере.

> `/etc/default/prometheus` — это `EnvironmentFile` systemd, а не шелл. `${ARGS:-}`
> в нём не раскрывается и уезжает в аргументы как есть: `unexpected ${ARGS:-}`,
> сервис не стартует. Писать `ARGS="--web.listen-address=..."` целиком.
