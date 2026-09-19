#!/usr/bin/env bash
# A18 — среда узла: кто сидит за клавиатурой, что умеет sudo, чем зашифрован swap.
#
# Проверка сверх списка ТЗ (там A1–A13). Появилась после аудита 18.09.2026 (п. 3.6):
# на `fels` нашлись автовход GDM на учётку с `sudo NOPASSWD: ALL`, незашифрованный
# swap-раздел и выключенный Secure Boot — а документы утверждали обратное
# (docs/adr/0009-no-full-disk-encryption.md, таблица компенсаций).
#
# Этого теста не хватало по той же причине, что и A14: остальные проверки смотрят на
# узел изнутри контура hearth (файлы, юниты, счётчики) и не видят среду, в которой он
# стоит. А ломается тут ровно одно свойство, на котором держится всё остальное:
#
#   автовход на учётку с sudo   -> десять секунд у телевизора = ключ CA релея
#   NOPASSWD: ALL               -> то же самое, но и по ssh с чужого ключа
#   swap без шифрования         -> копии памяти hearthd (пароли очередей,
#                                  static-auth-secret) остаются на диске
#   coturn старее кандидата     -> публичный порт 3478 без вышедшего фикса
#
# Скрипт ТОЛЬКО СМОТРИТ. Он не правит ни файлов, ни служб, ни правил — ни при каком
# исходе. Что делать с его вердиктом: docs/runbook-host-hardening.md.
#
# Запуск: sudo tests/acceptance/a18-host-env.sh
set -uo pipefail

# Пин версии coturn. Значение = то, что стоит на узле и является кандидатом в Debian 13
# на 18.09.2026 (обновления нет). Меняется вместе с записью в журнале обновлений.
COTURN_MIN="${COTURN_MIN:-4.6.1-2}"
GDM_CONF="${GDM_CONF:-/etc/gdm3/daemon.conf}"

status=0
bad()  { echo "  !!   $*"; status=1; }
ok()   { echo "  ok   $*"; }
info() { echo "  ?    $*"; }

[[ "$(uname -s)" == "Linux" ]] || { echo "не Linux — пропуск"; exit 77; }
[[ "$(id -u)" -eq 0 ]] || { echo "нужен root (sudo -l -U читает чужие права) — пропуск"; exit 77; }
command -v sudo >/dev/null || { echo "нет sudo — пропуск"; exit 77; }

# Права пользователя спрашиваем у самого sudo, а не разбором /etc/sudoers.d: правило
# может прийти из любого файла, из группы или из #includedir, и разбор текста врёт.
sudo_rules() { sudo -n -l -U "$1" 2>/dev/null; }

has_nopasswd() { sudo_rules "$1" | grep -q 'NOPASSWD'; }

in_sudo_group() {
    id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'
}

# Интерактивные люди: uid >= 1000, оболочка не заглушка. nobody (65534) не в счёт.
interactive_users() {
    awk -F: '$3 >= 1000 && $3 < 65000 && $7 !~ /(nologin|false|sync)$/ {print $1}' /etc/passwd
}

echo "== Автовход дисплей-менеджера"
autologin_user=""
if [[ -f "$GDM_CONF" ]]; then
    # Значение берём из первой некомментированной строки: закомментированный образец в
    # daemon.conf стоит по умолчанию и не должен считаться настройкой.
    enabled="$(grep -E '^[[:space:]]*AutomaticLoginEnable[[:space:]]*=' "$GDM_CONF" \
               | head -1 | cut -d= -f2- | tr -d '[:space:]')"
    autologin_user="$(grep -E '^[[:space:]]*AutomaticLogin[[:space:]]*=' "$GDM_CONF" \
               | head -1 | cut -d= -f2- | tr -d '[:space:]')"
    case "${enabled,,}" in
        true|1|yes)
            if [[ -z "$autologin_user" ]]; then
                bad "$GDM_CONF: автовход включён, но пользователь не указан — GDM не поднимет сессию"
            else
                echo "       автовход включён, пользователь: $autologin_user"
                if in_sudo_group "$autologin_user"; then
                    bad "$autologin_user состоит в группе sudo/admin — автовход даёт root без пароля у клавиатуры"
                    echo "       docs/runbook-host-hardening.md §1.2 и §2.1"
                elif has_nopasswd "$autologin_user"; then
                    bad "$autologin_user имеет правило NOPASSWD — автовход даёт root без пароля у клавиатуры"
                else
                    ok "$autologin_user не имеет sudo — автовход допустим (эталон runbook-install-beelink.md §3)"
                fi
            fi
            ;;
        ""|false|0|no) ok "автовход выключен в $GDM_CONF" ;;
        *)             info "$GDM_CONF: AutomaticLoginEnable=$enabled — значение не распознано, проверьте глазами" ;;
    esac
else
    info "$GDM_CONF отсутствует — GDM на узле не настроен"
    for f in /etc/lightdm/lightdm.conf /etc/sddm.conf; do
        [[ -f "$f" ]] && grep -qiE '^[[:space:]]*(autologin-user|User)[[:space:]]*=' "$f" \
            && bad "$f содержит автовход — проверьте его тем же правилом (учётка без sudo)"
    done
fi

echo
echo "== Графическая сессия"
if command -v loginctl >/dev/null 2>&1; then
    found_gui=0
    while read -r sid; do
        [[ -n "$sid" ]] || continue
        stype="$(loginctl show-session "$sid" -p Type --value 2>/dev/null)"
        [[ "$stype" == "wayland" || "$stype" == "x11" ]] || continue
        found_gui=1
        suser="$(loginctl show-session "$sid" -p User --value 2>/dev/null)"
        sname="$(loginctl show-session "$sid" -p Name --value 2>/dev/null)"
        sactive="$(loginctl show-session "$sid" -p Active --value 2>/dev/null)"
        slocked="$(loginctl show-session "$sid" -p LockedHint --value 2>/dev/null)"
        echo "       сессия $sid: $sname (uid $suser), $stype, Active=$sactive, LockedHint=$slocked"
        if in_sudo_group "$sname" || has_nopasswd "$sname"; then
            bad "владелец графической сессии ($sname) имеет sudo — незалоченный экран равен root-шеллу"
        else
            ok "владелец графической сессии ($sname) не имеет sudo"
        fi
    done < <(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
    [[ $found_gui -eq 0 ]] && info "графических сессий нет (узел без десктопа или сессия не поднята)"
else
    info "нет loginctl — состояние сессии не проверено"
fi

echo
echo "== sudo: кому разрешено без пароля"
# NOPASSWD у человека — это не «удобно», это отмена пароля как барьера: тот же эффект,
# что у пустого пароля, только незаметный. Демону sudo не нужен вовсе: hearthd работает
# от hearth с CAP_NET_ADMIN и правилом polkit 49-hearthd.rules.
nopasswd_found=0
while read -r u; do
    [[ -n "$u" ]] || continue
    if has_nopasswd "$u"; then
        bad "$u: NOPASSWD — пароль как барьер отменён (docs/runbook-host-hardening.md §1.2)"
        sudo_rules "$u" | grep 'NOPASSWD' | sed 's/^/         /'
        nopasswd_found=1
    fi
done < <(interactive_users)
[[ $nopasswd_found -eq 0 ]] && ok "ни у одного интерактивного пользователя нет NOPASSWD"

for svc in hearth simplex turnserver simplex-ntf; do
    id -u "$svc" >/dev/null 2>&1 || continue
    if sudo_rules "$svc" | grep -q '(ALL'; then
        bad "$svc (служебная учётка) имеет права sudo — их не должно быть ни одной"
    fi
done

echo
echo "== Шифрование: swap"
# Swap — единственная часть диска, которую можно зашифровать без переустановки и без
# «ключа рядом с замком»: он не обязан пережить перезагрузку, потому что гибернация
# замаскирована (hearthd/deploy/install.sh, блок 8). Ключ берётся из /dev/urandom.
if ! command -v swapon >/dev/null 2>&1; then
    info "нет swapon — не проверено"
else
    swap_list="$(swapon --show=NAME --noheadings 2>/dev/null)"
    if [[ -z "$swap_list" ]]; then
        ok "swap не подключён — шифровать нечего"
    else
        while read -r dev; do
            [[ -n "$dev" ]] || continue
            if [[ "$dev" == /dev/zram* ]]; then
                ok "$dev — zram, на диск ничего не попадает"
            elif [[ "$dev" != /dev/* ]]; then
                bad "$dev — swap-файл на обычной ФС, содержимое памяти лежит открыто (§2.2)"
            elif command -v dmsetup >/dev/null 2>&1 \
                 && dmsetup table "$dev" 2>/dev/null | awk '{print $3}' | grep -qx crypt; then
                ok "$dev — поверх dm-crypt"
            else
                bad "$dev — swap БЕЗ шифрования: копии памяти hearthd (пароли очередей,"
                echo "       static-auth-secret) остаются на диске. docs/runbook-host-hardening.md §2.2"
            fi
        done <<<"$swap_list"
    fi
fi

# Гибернация и случайный ключ несовместимы. Проверяем всегда: размаскировали один раз —
# и первая же гибернация превратится в порчу данных.
for t in hibernate.target hybrid-sleep.target suspend.target sleep.target; do
    state="$(systemctl is-enabled "$t" 2>/dev/null)"
    [[ "$state" == "masked" ]] || bad "$t не замаскирован ($state) — сон узла останавливает доставку, а гибернация ломает шифрованный swap"
done

echo
echo "== Шифрование: остальной диск (справочно, решение принято в ADR 0009)"
if command -v lsblk >/dev/null 2>&1; then
    luks="$(lsblk -o FSTYPE --noheadings 2>/dev/null | grep -c crypto_LUKS)"
    if [[ "$luks" -gt 0 ]]; then
        ok "разделов crypto_LUKS: $luks"
    else
        info "LUKS нет — принятое отступление, docs/adr/0009-no-full-disk-encryption.md"
    fi
fi

echo
echo "== Загрузка (справочно: без FDE Secure Boot ничего не даёт, §3.3)"
if command -v mokutil >/dev/null 2>&1; then
    info "SecureBoot: $(mokutil --sb-state 2>&1 | head -1)"
    setup="$(mokutil --sb-state 2>&1 | grep -i 'setup mode')"
    [[ -n "$setup" ]] && info "платформа в Setup Mode: свои ключи запишет любой, у кого есть BIOS"
else
    info "нет mokutil — состояние Secure Boot не снято"
fi
[[ -e /sys/class/tpm/tpm0 ]] && info "TPM присутствует (/sys/class/tpm/tpm0)" \
                             || info "TPM не виден — вариант «LUKS + разблокировка по TPM» недоступен"

echo
echo "== coturn: версия пакета на публичном порту 3478"
if ! command -v dpkg-query >/dev/null 2>&1; then
    info "не dpkg-система — версия coturn не проверена"
elif ! installed="$(dpkg-query -W -f='${Version}' coturn 2>/dev/null)" || [[ -z "$installed" ]]; then
    info "coturn не установлен"
else
    echo "       установлено: $installed (пин: $COTURN_MIN)"
    [[ "$installed" == "$COTURN_MIN" ]] \
        || info "версия отличается от пина — обновите COTURN_MIN и запись в docs/runbook-updates.md"
    if command -v apt-cache >/dev/null 2>&1; then
        cand="$(apt-cache policy coturn 2>/dev/null | awk '/Candidate:/{print $2}')"
        if [[ -z "$cand" || "$cand" == "(none)" ]]; then
            info "кандидат не определён (кеш apt пуст?) — сверьте вручную: apt-cache policy coturn"
        elif [[ "$cand" == "$installed" ]]; then
            ok "кандидат совпадает с установленным ($cand) — обновлять нечего"
        else
            bad "доступно обновление coturn: $installed -> $cand (критерий ТЗ §1.4: ≤ 7 дней)"
            echo "       порядок обновления: docs/runbook-host-hardening.md §2.3"
        fi
    fi
fi

echo
if [[ $status -eq 0 ]]; then
    echo "Среда узла соответствует записанным решениям."
else
    echo "Есть расхождения. Что с ними делать: docs/runbook-host-hardening.md"
    echo "Ни одно из них этот скрипт не чинит — он только смотрит."
fi
exit $status
