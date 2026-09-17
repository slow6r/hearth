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

## Проверка после правок sshd

Порядок, который не оставляет запертой двери: не закрывать текущую сессию, пока новая
не открылась.

```bash
sudo sshd -t                 # конфиг валиден
sudo systemctl reload ssh    # reload, не restart
ssh fels@192.168.1.72 true   # из ДРУГОГО окна, старая сессия ещё жива
```

Бэкап конфига перед правкой кладётся в `/root/99-server.conf.pre-<что>-<дата>`.
