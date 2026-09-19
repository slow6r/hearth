# Runbook: доступ аудитора к узлу

Аудит смотрит конфиги и журналы, а не управляет узлом. Поэтому у аудитора **своя
учётная запись без sudo**, а не ключ в `authorized_keys` пользователя `fels`: у `fels`
стоит `sudo NOPASSWD`, и его ключ — это полный root.

Этот файл существует по конкретной причине. 17 сентября 2026 аудит пришёл со своим
`auditor_ed25519` и получил `Permission denied (publickey)`. Разбор показал, что ключ
никто не отзывал — учётки `auditor` на `fels` не было никогда: узел развёрнут заново
9 сентября, а прежний доступ жил на старом хосте и нигде не был записан. Пока он не
записан здесь, он теряется при каждом переносе.

## Что уже сделано

На `fels` (`192.168.1.72`) заведено:

```
пользователь auditor   uid 1001, оболочка /bin/bash, группа только auditor
sudo                   нет
срок действия          бессрочно (chage -E -1 -M -1 -I -1)
sshd                   AllowUsers fels auditor
~/.ssh/authorized_keys 0600 auditor:auditor
```

sshd остаётся с `PasswordAuthentication no` и `PermitRootLogin no`: вход только по
ключу. Доступ снаружи дома не открывается — 22 порт наружу не проброшен (A4 это
проверяет), аудит заходит из домашней сети.

## Выдать доступ новому аудитору

Нужен **открытый** ключ — файл `*.pub`, одна строка `ssh-ed25519 AAAA... комментарий`.
Закрытый ключ не передаётся никогда и никому; просьба прислать именно его — повод
остановиться и переспросить голосом.

```bash
# на рабочей станции, ключ в файле auditor.pub
ssh fels@192.168.1.72 "sudo tee -a /home/auditor/.ssh/authorized_keys" < auditor.pub
ssh fels@192.168.1.72 "sudo chown auditor:auditor /home/auditor/.ssh/authorized_keys \
  && sudo chmod 600 /home/auditor/.ssh/authorized_keys"

# проверить, что легло ровно то, что ждали
ssh fels@192.168.1.72 "sudo ssh-keygen -lf /home/auditor/.ssh/authorized_keys"
```

Отпечаток из последней команды сверить с тем, что аудит называет у себя
(`ssh-keygen -lf auditor_ed25519.pub`). Совпал — доступ выдан тому, кому собирались.

`useradd` оставляет в `shadow` `!` — «учётка заблокирована». На Debian это входу по ключу не
мешает, но на части систем мешает, поэтому у `auditor` стоит `*`: пароля нет, блокировки нет.

```bash
ssh fels@192.168.1.72 "sudo usermod -p '*' auditor"
```

## Проверить, что доступ действительно работает

Чужим ключом войти нельзя, а «файлы разложены правильно» — это не проверка. Боевая проверка
делается временным ключом, который тут же отзывается.

```bash
ssh-keygen -t ed25519 -N "" -C temp-probe -f /tmp/probe -q
ssh fels@192.168.1.72 'sudo tee -a /home/auditor/.ssh/authorized_keys > /dev/null' < /tmp/probe.pub

ssh -i /tmp/probe auditor@192.168.1.72 'whoami; sudo -n true'
# ожидание: whoami → auditor; sudo → «требуется указать пароль»

# вернуть файл к одному настоящему ключу и убедиться, что временный отвергнут
ssh fels@192.168.1.72 'sudo tee /home/auditor/.ssh/authorized_keys > /dev/null' < auditor.pub
ssh -i /tmp/probe auditor@192.168.1.72 true    # ожидание: Permission denied (publickey)
rm -f /tmp/probe /tmp/probe.pub
```

Последние две строки обязательны: проверка, после которой остаётся лишний ключ, хуже отсутствия
проверки.

## Отозвать

```bash
ssh fels@192.168.1.72 "sudo truncate -s 0 /home/auditor/.ssh/authorized_keys"
```

Учётку при этом можно не трогать: без ключей и без пароля войти нечем. Если нужно
убрать совсем — `sudo userdel -r auditor` и убрать `auditor` из `AllowUsers` в
`/etc/ssh/sshd_config.d/99-server.conf`, затем `sudo sshd -t && sudo systemctl reload ssh`.

## Что аудитор увидит и чего не увидит

Без дополнительных групп — почти ничего сверх своего домашнего каталога: `/etc/hearth`
это `0600 root:root`, журналы `systemd` закрыты. Это осознанно: расширять доступ надо
под конкретный запрос, а не заранее.

Если нужен разбор журналов, добавляется ровно столько:

```bash
ssh fels@192.168.1.72 "sudo usermod -aG systemd-journal,adm auditor"   # только чтение
```

`systemd-journal` даёт `journalctl` по всем юнитам, `adm` — файлы в `/var/log`. Ни та,
ни другая группа не поднимает права. Дальше этого не идти: всё, что требует чтения
секретов из `/etc/hearth`, аудит получает выгрузкой от владельца, а не своим доступом.

## Выгрузки для аудита

Принцип «всё, что требует чтения секретов, аудит получает выгрузкой от владельца»
теперь исполняется скриптом, а не памятью. Механизм один на все запросы:

```bash
sudo hearthd/deploy/audit-dump.sh              # → /home/auditor/dump-<дата>/
```

Внутри ровно четырнадцать файлов и ничего сверх: паспорта сборки обоих бинарников,
их измеренные хеши, манифест и результат его проверки, состояние узла, история
инцидентов сторожа утечки, реестр устройств **без токенов**, список аудиторских
токенов, юниты, правила nftables, журнал `hearthd` и хеши раздаваемых файлов. Плюс
`SHA256SUMS`, с которого проверяющий начинает.

Обезличивание — это выбор источников, а не постобработка: ни один пункт не читает
`/etc/hearth/secrets`, приватные ключи PKI и age-идентичность. Единственное место, где
иначе утекли бы токены устройств, закрыто проекцией внутри `hearthctl`
(`device list --redacted`), а не фильтром на выходе — фильтр переживает ровно до
появления следующего секретного поля.

## Как аудитор проверяет, что работает заявленный код

Это единственная цепочка, ради которой всё перечисленное ниже существует. Она
замыкается без единого нового права: `readlink /proc/<pid>/exe` требует ptrace, а
ptrace — это заодно чтение памяти релеев, то есть переписки (ТЗ §7.4), поэтому
такого доступа не будет никогда.

```bash
# 1. что говорит о себе работающий процесс (нужны группы systemd-journal,adm)
journalctl -u hearthd | grep -o 'commit=[0-9a-f]\{40\} .*exe_sha256=[0-9a-f]\{64\}' | tail -1

# 2. что лежит на диске (ACL на один файл, выдаётся владельцем)
sha256sum /usr/local/bin/hearthd          # обязан совпасть с exe_sha256

# 3. из какого дерева это собрано
hearthd build-info                         # commit, tree_sha256, dirty

# 4. то же дерево, выложенное для чтения
grep tree_sha256 /srv/hearth/src-<commit>/hearth-src-<commit>.manifest.txt
```

Совпали все четыре — значит читаемые исходники и есть исходники работающего файла.
Выгрузку исходников делает `hearthd/deploy/publish-src.sh`: она содержит только
отслеживаемые git файлы ровно одного коммита, поэтому ключи из `keys/` в неё не
попадают физически, а не по договорённости с тем, кто копировал.

Предел утверждения назван прямо: паспорт доказывает «собрано из такого дерева», а не
«в дереве нет закладки». Второе доказывается чтением кода — ради него выгрузка и
делается.

## Авторизованный GET боевого узла

Проверить раздаваемую сборку своими руками можно, не получая токена члена семьи.
Владелец выписывает срочный токен с перечисленной областью:

```bash
hearthctl audit-token issue --ttl-hours 48 --max-uses 5 --scope updates \
    --note 'аудит 2026-09' --write-token /home/auditor/audit.token
```

Аудитор предъявляет его заголовком:

```bash
curl -H "x-hearth-audit-token: $(cat audit.token)" \
     https://<узел>:<порт device api>/updates/manifest.json
curl -H "x-hearth-audit-token: $(cat audit.token)" -O \
     https://<узел>:<порт device api>/updates/<файл>.apk
sha256sum <файл>.apk    # обязан совпасть с 14-updates.sha256 из выгрузки
```

Что этот токен НЕ открывает: `/turn-credentials`, стикеры, реестр устройств, bundle.
Слот `max_devices` он не расходует. Срок и счётчик обязательны — бессрочного варианта
в коде нет. Отзыв действует немедленно:

```bash
hearthctl audit-token list
hearthctl audit-token revoke <id>
```

## Выгрузка состояния среды под запрос аудита

Аудит 18.09.2026 закрыл п. 3.6 наполовину и честно написал: «текущая графическая сессия
и полный sudoers не проверены; свежий закрытый TURN config не прочитан». Это не
недосмотр аудитора — так устроен доступ: учётка `auditor` без групп не видит ни
`/etc/sudoers.d`, ни `/etc/hearth/turn` (каталог `2750 hearth:turnserver`), ни чужую
графическую сессию.

**Прав аудитору не добавляем.** `usermod -aG hearth auditor` или добавление в
`turnserver` отдаёт живой `static-auth-secret` и пароли создания очередей — то есть
ровно те замки, на которых стоит публичный релей ([ADR 0007](adr/0007-public-relay-no-vpn.md)).
Вместо этого владелец выполняет фиксированный набор **читающих** команд и отдаёт вывод.

Первым делом — сам тест: он отвечает на большую часть вопросов без сырых конфигов.

```bash
sudo tests/acceptance/a18-host-env.sh
```

Если нужна сырая картина, она снимается так (всё только читает):

```bash
# Графическая сессия
loginctl list-sessions
loginctl show-session <id> -p Id -p User -p Name -p Type -p Class -p Remote -p Active \
                          -p LockedHint -p IdleHint
grep -vE '^[[:space:]]*(#|$)' /etc/gdm3/daemon.conf
sudo -u <user> dconf read /org/gnome/desktop/screensaver/lock-enabled
sudo -u <user> dconf read /org/gnome/desktop/session/idle-delay

# sudoers целиком
sudo cat /etc/sudoers
sudo ls -l /etc/sudoers.d/
sudo grep -rvE '^[[:space:]]*(#|$)' /etc/sudoers.d/
sudo -n -l -U fels
sudo -n -l -U auditor
getent group sudo adm systemd-journal
awk -F: '$3>=1000 && $7 !~ /nologin|false/' /etc/passwd

# Загрузка и шифрование
mokutil --sb-state
bootctl status          # или efibootmgr -v
lsblk -o NAME,FSTYPE,TYPE,SIZE,MOUNTPOINT
cat /etc/crypttab; cat /proc/swaps; swapon --show
sudo dmsetup ls --target crypt; zramctl

# coturn
dpkg-query -W -f='${Version}\n' coturn
apt-cache policy coturn
systemctl cat coturn
systemctl show coturn -p User -p Group -p ExecStart
sudo stat -c '%a %U:%G %n' /etc/hearth/turn /etc/hearth/turn/turnserver.conf /etc/turnserver.conf
```

**Конфиг TURN — никогда `cat`.** 9 сентября живой `static-auth-secret` уже был выведен
в переписку при чтении конфига; секрет пришлось менять и перезапускать coturn
([журнал развёртывания](deploy-fels-2026-09-09.md)). Второй раз это стоит ротации и
перевыпуска bundle на всех устройствах семьи. Поэтому — одной командой, с маскировкой:

```bash
sudo sed -E 's/^(static-auth-secret=).*/\1<REDACTED>/' /etc/hearth/turn/turnserver.conf
sudo sha256sum /etc/hearth/turn/turnserver.conf /etc/turnserver.conf
```

Совпадение двух хешей показывает, что отрендеренный и действующий файлы — один и тот
же, и для этого содержимое раскрывать не требуется.

## Проверка после правок sshd

Порядок, который не оставляет запертой двери: не закрывать текущую сессию, пока новая
не открылась.

```bash
sudo sshd -t                 # конфиг валиден
sudo systemctl reload ssh    # reload, не restart
ssh fels@192.168.1.72 true   # из ДРУГОГО окна, старая сессия ещё жива
```

Бэкап конфига перед правкой кладётся в `/root/99-server.conf.pre-<что>-<дата>`.
