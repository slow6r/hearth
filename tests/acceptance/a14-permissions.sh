#!/usr/bin/env bash
# A14 — права доступа согласованы с тем, что демону реально нужно.
#
# Тест сверх списка ТЗ (там A1–A13): аудит показал, что остальные проверяли режим
# файла, но не владельца — а ломается именно владелец.
#
# Этого теста не хватало: остальные проверяли режим файла (0600), но не владельца.
# А ломается именно владелец: init-скрипты и `hearthd ca init` работают от root,
# демон — от пользователя hearth. Несогласованность не мешает старту, она ломает
# функции по одной и молча:
#
#   секреты недоступны      -> выпуск bundle и ротация TURN падают с EACCES
#   fingerprint недоступен  -> у клиента нет адреса релея
#   /var/opt/simplex закрыт -> ночной бэкап падает каждую ночь
#   server.key недоступен   -> admin API не поднимается
#
# Чинится: sudo hearthd/deploy/fix-permissions.sh
set -uo pipefail

HEARTH_USER="${HEARTH_USER:-hearth}"
status=0

id -u "$HEARTH_USER" >/dev/null 2>&1 || { echo "нет пользователя $HEARTH_USER — пропуск"; exit 77; }
command -v sudo >/dev/null || { echo "нет sudo — пропуск"; exit 77; }

# Может ли hearth прочитать файл? Спрашиваем ядро, а не разбираем биты вручную:
# группы, ACL и прочее так учитываются сами.
can_read() {
    sudo -u "$HEARTH_USER" test -r "$1" 2>/dev/null
}
can_traverse() {
    sudo -u "$HEARTH_USER" test -x "$1" 2>/dev/null
}

check_readable() {
    local path="$1" why="$2"
    if [[ ! -e "$path" ]]; then
        echo "  ?    $path отсутствует ($why)"
        return
    fi
    if can_read "$path"; then
        echo "  ok   $path читается"
    else
        echo "  !!   $path НЕ читается пользователем $HEARTH_USER — $why"
        status=1
    fi
}

echo "== Членство в группе simplex (чтение состояния релеев)"
if id -nG "$HEARTH_USER" | tr ' ' '\n' | grep -qx simplex; then
    echo "  ok   $HEARTH_USER состоит в группе simplex"
else
    echo "  !!   $HEARTH_USER НЕ состоит в группе simplex — бэкап и bundle сломаны"
    status=1
fi

echo
echo "== Секреты релеев (нужны для выпуска bundle)"
check_readable /etc/hearth/secrets            "каталог секретов"
check_readable /etc/hearth/secrets/smp-create-password  "пароль очередей -> адрес в bundle"
check_readable /etc/hearth/secrets/xftp-create-password "пароль загрузки файлов"
check_readable /etc/hearth/secrets/turn-secret          "ротация и креды TURN"

echo
echo "== Состояние релеев (нужно для bundle и бэкапа)"
for d in /etc/opt/simplex /var/opt/simplex; do
    if [[ -d "$d" ]]; then
        if can_traverse "$d"; then
            echo "  ok   $d проходим"
        else
            echo "  !!   $d недоступен — ночной бэкап будет падать"
            status=1
        fi
    else
        echo "  ?    $d отсутствует (релей не инициализирован)"
    fi
done
check_readable /etc/opt/simplex/fingerprint "отпечаток CA -> адрес релея в bundle"

# Push-сервер (ADR 0016) — только на узле, где он заведён. Его каталоги демону нужны
# ровно так же, как каталоги релеев: их архивирует ночной бэкап.
if id -u simplex-ntf >/dev/null 2>&1; then
    echo
    echo "== Push-сервер (ADR 0016)"
    if id -nG "$HEARTH_USER" | tr ' ' '\n' | grep -qx simplex-ntf; then
        echo "  ok   $HEARTH_USER состоит в группе simplex-ntf"
    else
        echo "  !!   $HEARTH_USER НЕ состоит в группе simplex-ntf — бэкап push-сервера сломан"
        status=1
    fi
    for d in /etc/opt/simplex-ntf /var/opt/simplex-ntf; do
        if [[ ! -d "$d" ]]; then
            echo "  ?    $d отсутствует (init-ntf.sh не запускался)"
        elif can_traverse "$d"; then
            echo "  ok   $d проходим"
        else
            echo "  !!   $d недоступен — ночной бэкап будет падать"
            status=1
        fi
    done
    # Ключ APNs подписывает пуши от имени команды Apple. Читать его на диске не должен
    # никто, кроме root: службе его отдаёт systemd через LoadCredential.
    APNS_KEY=/etc/credstore/hearth-apns.p8
    if [[ -e "$APNS_KEY" ]]; then
        if can_read "$APNS_KEY" || sudo -u simplex-ntf test -r "$APNS_KEY" 2>/dev/null; then
            echo "  !!   $APNS_KEY читается не только root — должно быть 0600 root:root"
            status=1
        else
            echo "  ok   ключ APNs доступен только root"
        fi
    else
        echo "  ?    $APNS_KEY отсутствует (docs/runbook-ntf.md, шаг 4)"
    fi
fi

echo
echo "== TLS-материал admin API"
check_readable /etc/hearth/pki/server.pem "сертификат admin API"
check_readable /etc/hearth/pki/server.key "ключ admin API — без него демон не поднимет админку"
check_readable /etc/hearth/pki/ca.pem     "CA для проверки клиентских сертификатов"

echo
echo "== Что демону быть доступно НЕ должно"
if [[ -f /etc/hearth/pki/ca.key ]]; then
    if can_read /etc/hearth/pki/ca.key; then
        echo "  !!   ca.key ЧИТАЕТСЯ демоном — компрометация hearthd даст право"
        echo "       выписать себе админский сертификат. Должно быть 0600 root:root."
        status=1
    else
        echo "  ok   ca.key демону недоступен"
    fi
else
    echo "  ?    ca.key отсутствует — hearthd ca init ещё не запускался"
fi

# Приватные ключи админов на узле оставаться не должны.
shopt -s nullglob
for f in /etc/hearth/pki/*.key; do
    base="$(basename "$f")"
    # device-api.key — TLS-ключ device API, который демон отдаёт телефонам на 7444.
    # Он обязан лежать на узле ровно по той же причине, что и server.key выше: без
    # приватного ключа TLS-сервер не поднимется, и обновления с TURN-кредами перестанут
    # раздаваться. Имя задано в hearthd/src/pki/mod.rs (DEVICE_API_KEY).
    #
    # Список исключений написан до появления device API, поэтому тест считал штатный
    # файл забытым админским ключом и падал на каждом прогоне.
    [[ "$base" == "ca.key" || "$base" == "server.key" || "$base" == "device-api.key" ]] && continue
    echo "  !!   $f — приватный ключ админа на узле. Перенесите на рабочую станцию."
    status=1
done
shopt -u nullglob

echo
if [[ $status -eq 0 ]]; then
    echo "Права согласованы."
else
    echo "Есть расхождения. Чинится: sudo hearthd/deploy/fix-permissions.sh"
fi
exit $status
