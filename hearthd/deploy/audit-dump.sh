#!/usr/bin/env bash
# Выгрузка состояния узла для аудита (DUMP-1).
#
#   sudo hearthd/deploy/audit-dump.sh [каталог]
#
# ГДЕ ЗАПУСКАТЬ. На узле, владельцем, через sudo. Результат по умолчанию —
# /home/auditor/dump-<дата>/, доступный аудитору на чтение по ACL.
#
# ЗАЧЕМ. Принцип «аудит получает выгрузкой от владельца» записан в
# docs/runbook-auditor-access.md, а механизма не было: каждая выгрузка делалась руками
# заново, и состав прошлой восстанавливался чтением журнала развёртывания. Это та же
# болезнь, которую проект уже диагностировал про учётку auditor — «доступ существовал
# только в чьей-то памяти и не пережил переноса».
#
# ОБЕЗЛИЧИВАНИЕ — ЭТО ВЫБОР ИСТОЧНИКОВ, А НЕ ПОСТОБРАБОТКА. Ни один пункт ниже не
# читает /etc/hearth/secrets, приватные ключи PKI, age-идентичность и содержимое
# переписки. Единственное место, где иначе утекли бы токены устройств, закрыто не
# фильтром на выходе, а проекцией в самом hearthctl (`device list --redacted`):
# вырезание поля постфактум переживает ровно до появления следующего секретного поля.
#
# ЧТО ЗДЕСЬ ЕСТЬ, А ЧЕГО НЕТ. Есть: паспорта бинарников, их хеши, манифест, состояние
# узла и сторожа утечки, юниты, правила firewall, журнал демона, хеши раздаваемых
# файлов. Нет: ни одного секрета, ни одного адреса переписки, ни одного сообщения.
set -euo pipefail

DEST="${1:-/home/auditor/dump-$(date -u +%Y-%m-%d)}"

if [ "$(id -u)" -ne 0 ]; then
    echo "audit-dump.sh запускается через sudo: часть источников читает только root" >&2
    exit 1
fi

# Ошибка одного пункта не должна отменять выгрузку целиком — но и молчать о ней
# нельзя: отсутствующий раздел обязан отличаться от пустого.
FAILED=()
collect() {
    local name="$1"; shift
    if "$@" > "$DEST/$name" 2> "$DEST/$name.err"; then
        [ -s "$DEST/$name.err" ] || rm -f "$DEST/$name.err"
        echo "   $name"
    else
        FAILED+=("$name")
        echo "   $name — НЕ СОБРАНО (см. $name.err)" >&2
    fi
}

SINCE="${HEARTH_DUMP_SINCE:-30 days ago}"

install -d -m 0750 -o root -g root "$DEST"
echo "== выгрузка в $DEST"

# 1. Целостность: совпадает ли то, что на диске, с тем, что запинено.
collect 01-manifest-verify.json   hearthctl --json manifest verify
collect 02-manifest.toml          cat /etc/hearth/manifest.toml

# 2. Паспорта сборки: из какого дерева собраны установленные файлы.
collect 03-hearthd.build-info     hearthd build-info
collect 04-hearthctl.build-info   hearthctl build-info
collect 05-installed.build-info   cat /var/lib/hearth/installed.build-info

# 3. Хеши всего, что узел исполняет. Отдельно от манифеста: манифест — утверждение,
#    а это измерение. Расхождение между ними и есть находка.
collect 06-binaries.sha256 sha256sum \
    /usr/local/bin/hearthd /usr/local/bin/hearthctl \
    /usr/local/bin/smp-server /usr/local/bin/xftp-server \
    /usr/bin/turnserver

# 4. Состояние узла целиком: режим, здоровье, целостность, бэкап, счётчики.
collect 07-status.json            hearthctl --json status
# 5. Сторож утечки — то самое число, которое обязано быть нулём (ТЗ §5.4).
collect 08-egress-incidents.json  hearthctl --json egress --incidents
# 6. Устройства БЕЗ токенов: см. шапку про проекцию.
collect 09-devices-redacted.json  hearthctl --json device list --redacted
# 7. Аудиторские токены: чем именно проверяющему открыли дверь и на сколько.
#    Секретов в этом списке нет по построению (`AuditToken::public`).
collect 10-audit-tokens.json      hearthctl --json audit-token list

# 8. Как узел настроен на самом деле — юниты и правила, а не то, что лежит в git.
collect 11-units.txt              systemctl cat hearthd smp-server xftp-server coturn
collect 12-nft-ruleset.txt        nft list ruleset
collect 13-journal-hearthd.txt    journalctl -u hearthd --since "$SINCE" --no-pager

# 9. Что узел раздаёт телефонам: хеши манифеста обновления, подписи и самого APK.
#    Аудитор качает их сам аудиторским токеном и сверяет с этими числами.
collect 14-updates.sha256 sh -c 'find /srv/hearth/updates -maxdepth 1 -type f -print0 | sort -z | xargs -0 -r sha256sum'

echo "== контрольные суммы выгрузки"
( cd "$DEST" && find . -maxdepth 1 -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 -r sha256sum > SHA256SUMS )

echo "== права"
chown -R root:root "$DEST"
find "$DEST" -type f -exec chmod 0644 {} +
chmod 0755 "$DEST"
# ACL, а не группа: право читать выдаётся одному человеку и снимается одной командой,
# не затрагивая ничего больше. Группа бы жила дольше, чем аудит.
if command -v setfacl >/dev/null 2>&1; then
    setfacl -R -m u:auditor:rX "$DEST"
    setfacl -R -d -m u:auditor:rX "$DEST"
else
    echo "   setfacl не установлен — выдайте доступ руками (apt install acl)" >&2
fi

if [ ${#FAILED[@]} -gt 0 ]; then
    echo
    echo "НЕ СОБРАНО: ${FAILED[*]}" >&2
    echo "Отсутствующий раздел — это не пустой раздел. Разберитесь до передачи." >&2
fi

cat <<NEXT

== что передать аудитору

   Каталог $DEST целиком. Внутри SHA256SUMS: проверяющий начинает с
   \`sha256sum -c SHA256SUMS\`, чтобы дальше говорить о неизменной выгрузке.

== чего в выгрузке нет и почему

   * /etc/hearth/secrets — пароли релеев; это вход в контур, а не свидетельство.
   * приватные ключи PKI и age-идентичность — по той же причине.
   * токены устройств — обезличены проекцией (device list --redacted).
   * содержимое переписки — узел его не читает вовсе (ТЗ §7.4), читать нечего.

NEXT
