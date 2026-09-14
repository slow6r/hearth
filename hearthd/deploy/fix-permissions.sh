#!/usr/bin/env bash
# Привести владельцев и права в согласие с тем, что демону реально нужно.
#
#   sudo ./fix-permissions.sh [--dry-run]
#
# Идемпотентно. Запускать после:
#   * init-скриптов релеев (они пишут от root — файлы остаются root:root);
#   * `hearthd ca init` (тоже от root — server.key остаётся 0600 root:root);
#   * ручной правки чего-либо в /etc/hearth или /etc/opt/simplex.
#
# ЗАЧЕМ ЭТО ОТДЕЛЬНЫМ СКРИПТОМ. hearthd работает от пользователя `hearth`, а почти всё
# его состояние создаётся root'ом или пользователем `simplex`. Несогласованность прав
# не ломает старт демона — она ломает функции по одной и молча:
#
#   секреты недоступны  -> выпуск bundle и ротация TURN падают с EACCES
#   fingerprint недоступен -> у клиента нет адреса релея
#   /var/opt/simplex недоступен -> ночной бэкап падает с алертом каждую ночь
#   server.key недоступен  -> admin API не поднимается
#
# Проверяется acceptance-тестом a14-permissions.sh.
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  would: $*"
    else
        "$@"
    fi
}

note() { printf '  %s\n' "$*"; }
skip() { printf '  -- %s\n' "$*"; }

if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
    echo "нужны права root (или --dry-run)" >&2
    exit 1
fi

id -u hearth  >/dev/null 2>&1 || { echo "нет пользователя hearth — сначала install.sh" >&2; exit 1; }
id -u simplex >/dev/null 2>&1 || { echo "нет пользователя simplex — сначала install.sh" >&2; exit 1; }

echo "== hearth должен состоять в группе simplex (чтение состояния релеев)"
if id -nG hearth | tr ' ' '\n' | grep -qx simplex; then
    note "уже состоит"
else
    run usermod -aG simplex hearth
    note "добавлен — hearthd подхватит после рестарта"
fi

echo
echo "== каталоги релеев: группа simplex, чтение группе"
for dir in /etc/opt/simplex /var/opt/simplex /etc/opt/simplex-xftp /var/opt/simplex-xftp; do
    if [[ -d "$dir" ]]; then
        run chgrp -R simplex "$dir"
        run chmod -R g+rX "$dir"
        note "$dir"
    else
        skip "$dir отсутствует (релей ещё не инициализирован)"
    fi
done

echo
echo "== push-сервер (ADR 0016): группа simplex-ntf, ключ APNs только root"
if id -u simplex-ntf >/dev/null 2>&1; then
    if id -nG hearth | tr ' ' '\n' | grep -qx simplex-ntf; then
        note "hearth уже в группе simplex-ntf"
    else
        run usermod -aG simplex-ntf hearth
        note "hearth добавлен в группу simplex-ntf — hearthd подхватит после рестарта"
    fi
    for dir in /etc/opt/simplex-ntf /var/opt/simplex-ntf; do
        if [[ -d "$dir" ]]; then
            run chgrp -R simplex-ntf "$dir"
            run chmod -R g+rX "$dir"
            note "$dir"
        else
            skip "$dir отсутствует (init-ntf.sh не запускался)"
        fi
    done
    # Ключ APNs подписывает пуши от имени команды Apple. Службе он приходит через
    # LoadCredential, поэтому на диске его не читает никто, кроме root — ни сама
    # служба, ни hearthd.
    if [[ -f /etc/credstore/hearth-apns.p8 ]]; then
        run chown root:root /etc/credstore/hearth-apns.p8
        run chmod 0600 /etc/credstore/hearth-apns.p8
        note "hearth-apns.p8 (0600 root:root)"
    fi
else
    skip "нет пользователя simplex-ntf — сначала install.sh"
fi

echo
echo "== секреты: каталог и файлы hearth:hearth, каталог 0750, файлы 0600"
# Каталог принадлежит демону, а не root. `hearthctl rotate turn-secret` пишет
# turn-secret атомарно (временный файл + rename), а для этого нужна запись в САМ
# КАТАЛОГ, не в файл. С root:hearth 0750 ротация падала с EACCES на
# `.../turn-secret.tmp.<pid>` — и падала бы каждые 30 дней.
#
# Права на чтение при этом не расширяются: 0750 закрывает каталог для всех, кроме
# root и hearth. Пароли релеев сюда по-прежнему пишет root (init-скрипты), и то,
# что демон теперь может их перезаписать, ничего не добавляет — он их и так читает,
# иначе не собрал бы bundle.
if [[ -d /etc/hearth/secrets ]]; then
    run chown hearth:hearth /etc/hearth/secrets
    run chmod 0750 /etc/hearth/secrets
    shopt -s nullglob
    for f in /etc/hearth/secrets/*; do
        [[ -f "$f" ]] || continue
        run chown hearth:hearth "$f"
        run chmod 0600 "$f"
        note "$(basename "$f")"
    done
    shopt -u nullglob
else
    skip "/etc/hearth/secrets отсутствует"
fi

echo
echo "== TLS-материал admin API: сертификат демону читаем, ключ CA — нет"
PKI=/etc/hearth/pki
if [[ -d "$PKI" ]]; then
    for f in server.pem ca.pem admins.json; do
        [[ -f "$PKI/$f" ]] || { skip "$PKI/$f отсутствует"; continue; }
        run chown root:hearth "$PKI/$f"
        run chmod 0640 "$PKI/$f"
        note "$f"
    done
    if [[ -f "$PKI/server.key" ]]; then
        run chown root:hearth "$PKI/server.key"
        run chmod 0640 "$PKI/server.key"
        note "server.key (0640 root:hearth)"
    fi
    # Ключ admin CA демону НЕ нужен: сертификаты выписывает `hearthd ca issue`
    # от root. Компрометация работающего демона не должна давать право выписать
    # себе новый админский сертификат.
    if [[ -f "$PKI/ca.key" ]]; then
        run chown root:root "$PKI/ca.key"
        run chmod 0600 "$PKI/ca.key"
        note "ca.key (0600 root:root — демону намеренно недоступен)"
    fi
    # Приватные ключи выписанных админов не должны оставаться на узле вообще.
    shopt -s nullglob
    for f in "$PKI"/*.key; do
        base="$(basename "$f")"
        [[ "$base" == "ca.key" || "$base" == "server.key" ]] && continue
        printf '  !! %s — приватный ключ админа на узле. Перенесите его на рабочую\n' "$base"
        printf '     станцию и удалите отсюда.\n'
    done
    shopt -u nullglob
else
    skip "$PKI отсутствует — сначала `hearthd ca init`"
fi

echo
echo "== состояние hearthd"
for dir in /var/lib/hearth /var/opt/hearth; do
    if [[ -d "$dir" ]]; then
        run chown -R hearth:hearth "$dir"
        note "$dir"
    else
        skip "$dir отсутствует"
    fi
done
# devices.json переехал в state_dir: демон пишет его атомарно, а это требует записи
# в каталог. В /etc/hearth это означало бы право переписать hearthd.toml и
# manifest.toml — см. комментарий у Paths::devices_file.
if [[ -f /etc/hearth/devices.json ]]; then
    printf '  !! /etc/hearth/devices.json — старое расположение.\n'
    printf '     Перенесите: mv /etc/hearth/devices.json /var/lib/hearth/devices.json\n'
    printf '     и повторите этот скрипт.\n'
fi
if [[ -f /var/lib/hearth/devices.json ]]; then
    run chown hearth:hearth /var/lib/hearth/devices.json
    run chmod 0640 /var/lib/hearth/devices.json
    note "devices.json (демон его пишет при выпуске bundle)"
fi

echo
echo "== конфиг coturn: пишет hearthd, читает turnserver"
# Две стороны одной задачи, и обе обязательны:
#   * каталог должен принадлежать hearth — запись атомарная, ей нужен каталог, а не файл;
#   * каталог должен быть setgid turnserver — иначе отрендеренный файл получит группу
#     hearth, и coturn (User=turnserver в юните Debian) его не прочитает.
# Права 0640 на сам файл ставит hearthd (store::MODE_SHARED_SECRET).
if id -u turnserver >/dev/null 2>&1; then
    run install -d -m 2750 -o hearth -g turnserver /etc/hearth/turn
    note "/etc/hearth/turn (2750 hearth:turnserver)"
    if [[ -f /etc/hearth/turn/turnserver.conf ]]; then
        run chown hearth:turnserver /etc/hearth/turn/turnserver.conf
        run chmod 0640 /etc/hearth/turn/turnserver.conf
        note "turnserver.conf"
    else
        skip "конфиг ещё не отрендерен — hearthctl rotate turn-secret"
    fi
    # turnserver обязан пройти сквозь /etc/hearth, чтобы дойти до своего каталога.
    run chmod 0751 /etc/hearth
    note "/etc/hearth 0751 (x без r: проход есть, листинга нет)"
else
    skip "нет пользователя turnserver — сначала apt install coturn"
fi
if [[ -f /etc/turnserver.conf ]]; then
    printf '  -- /etc/turnserver.conf: конфиг дистрибутива, hearth его не использует.\n'
    printf '     Юнит переведён на /etc/hearth/turn/turnserver.conf (см. drop-in).\n'
fi

cat <<'DONE'

Готово. Проверить:
  sudo tests/acceptance/a14-permissions.sh
  systemctl restart hearthd && hearthctl health
DONE
