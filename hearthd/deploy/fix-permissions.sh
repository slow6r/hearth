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
echo "== секреты: root:hearth 0640, каталог 0750"
if [[ -d /etc/hearth/secrets ]]; then
    run chown root:hearth /etc/hearth/secrets
    run chmod 0750 /etc/hearth/secrets
    shopt -s nullglob
    for f in /etc/hearth/secrets/*; do
        [[ -f "$f" ]] || continue
        run chown root:hearth "$f"
        run chmod 0640 "$f"
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
if [[ -f /etc/hearth/devices.json ]]; then
    run chown root:hearth /etc/hearth/devices.json
    run chmod 0660 /etc/hearth/devices.json
    note "devices.json (демон его пишет при выпуске bundle)"
fi

echo
echo "== turnserver.conf: hearthd перезаписывает его при ротации секрета"
if [[ -f /etc/turnserver.conf ]]; then
    run chown root:hearth /etc/turnserver.conf
    run chmod 0640 /etc/turnserver.conf
    note "/etc/turnserver.conf"
else
    skip "/etc/turnserver.conf отсутствует — создастся при hearthctl rotate turn-secret"
fi

cat <<'DONE'

Готово. Проверить:
  sudo tests/acceptance/a14-permissions.sh
  systemctl restart hearthd && hearthctl health
DONE
