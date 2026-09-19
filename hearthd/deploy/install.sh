#!/usr/bin/env bash
# hearth — node bootstrap (ТЗ §10.1, §11).
#
# Idempotent. Creates users and directories, installs units and the firewall, and
# stops before anything that needs a human decision (relay init, CA init, hash pinning).
#
# It does NOT download anything: the node has no egress (ТЗ §5.3). Bring the binaries
# with you on a USB stick, verified on another machine (ТЗ §6.1).
#
# Usage:  sudo ./install.sh [--dry-run]
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run() {
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  would run: $*"
    else
        "$@"
    fi
}

say() { printf '\n== %s\n' "$*"; }
warn() { printf '   ! %s\n' "$*" >&2; }

if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
    echo "install.sh must run as root (or use --dry-run)" >&2
    exit 1
fi

# --- 0. Предполётная проверка гейта режима -----------------------------------
#
# ДО ЛЮБЫХ ИЗМЕНЕНИЙ НА УЗЛЕ. Раньше эта проверка стояла на шаге 6 — то есть после
# замены бинарников, конфигов и юнитов и до `daemon-reload`. Обновление, при котором
# собрали не всё, обрывалось ровно посередине и оставляло узел полусобранным. Проверка
# ничего не меняет и не пишет: она только смотрит, чем будет исполняться гейт.
#
# ГЕЙТ БЕЗ ИСПОЛНИТЕЛЯ ХУЖЕ, ЧЕМ ОТСУТСТВИЕ ГЕЙТА: ExecCondition, который systemd не
# может запустить, отдаёт код 203, юнит помечается пропущенным — и релеи МОЛЧА не
# поднимаются ни сейчас, ни после перезагрузки.
say "0. предполётная проверка (ничего не меняет)"
GATE_BIN=""
for candidate in "$HERE/../target/x86_64-unknown-linux-musl/release/hearthctl" \
                 "$HERE/../target/release/hearthctl"; do
    [[ -f "$candidate" ]] || continue
    if [[ -n "$GATE_BIN" ]]; then
        echo "   найдены ДВА кандидата на hearthctl:" >&2
        echo "     $GATE_BIN" >&2
        echo "     $candidate" >&2
        echo "   Уберите лишний (rm) и повторите: ставить наугад нельзя." >&2
        exit 1
    fi
    GATE_BIN="$candidate"
done
# Ничего не собрано — годится уже установленный: сценарий «повторный запуск скрипта
# на живом узле» обязан работать.
if [[ -z "$GATE_BIN" && -x /usr/local/bin/hearthctl ]]; then
    GATE_BIN=/usr/local/bin/hearthctl
fi
if [[ -z "$GATE_BIN" ]]; then
    # В --dry-run это разбор сценария на машине разработчика, а не установка: там
    # собранного hearthctl может и не быть, и падать из-за этого незачем.
    if [[ $DRY_RUN -eq 1 ]]; then
        warn "hearthctl не найден — на живом узле это остановило бы установку здесь"
    else
        echo "   hearthctl не найден: ни собранного, ни установленного." >&2
        echo "   Гейт режима исполняет именно он; без него релеи не стартуют." >&2
        echo "   Соберите и повторите:" >&2
        echo "     cargo build --release --target x86_64-unknown-linux-musl" >&2
        exit 1
    fi
fi
if [[ $DRY_RUN -eq 0 && -n "$GATE_BIN" ]]; then
    # Мало того, что файл есть, — он должен РАБОТАТЬ на этой машине (не та архитектура,
    # не тот libc — те же 203/126 в итоге). Спрашиваем гейт про заведомо отсутствующий
    # файл: правильный ответ — 0, «режим не записан, стартовать можно».
    if ! "$GATE_BIN" mode gate --file /nonexistent/hearth-gate-selftest.json \
        >/dev/null 2>&1; then
        echo "   $GATE_BIN не отвечает на гейт режима." >&2
        echo "   Проверьте вручную:" >&2
        echo "     $GATE_BIN mode gate --file /nonexistent/x.json ; echo \$?   # ждём 0" >&2
        echo "   Пока это не исправлено, ставить нечего: релеи не стартуют." >&2
        exit 1
    fi
    echo "   гейт режима исполним: $GATE_BIN"
fi

say "1. users"
# System users, no shell, no home. The relays and hearthd never need to log in.
id -u simplex >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin simplex
id -u hearth  >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin hearth
# The push server (ADR 0016) gets its own user even on a node that never runs it, for
# two reasons that both fail hard rather than softly:
#   * hearth.nft names it in `meta skuid` — nft resolves names at load time, and one
#     unknown name makes the WHOLE ruleset fail to load (and the relays require it);
#   * hearthd.service lists its group in SupplementaryGroups — systemd refuses to start
#     a unit whose group does not exist.
# It is NOT `simplex`: the firewall lets exactly this uid reach Apple, and a shared uid
# would open that hole for smp-server and xftp-server too.
id -u simplex-ntf >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin simplex-ntf

# hearthd has to READ relay state that the relays own:
#   * /etc/opt/simplex/fingerprint       -> goes into every client bundle
#   * /etc/opt/simplex, /var/opt/simplex -> archived by the nightly backup
# Without this the bundle endpoint and the backup both fail every single time, with
# nothing but EACCES to explain it.
run usermod -aG simplex hearth
# Same for the push server's CA and database dump: archived by the nightly backup.
run usermod -aG simplex-ntf hearth

say "2. directories (ТЗ §10.1: everything the node owns lives in these)"
# 0750 with group `simplex`: the relays write, hearthd (in that group) reads.
run install -d -m 0750 -o simplex -g simplex /etc/opt/simplex /var/opt/simplex
run install -d -m 0750 -o simplex -g simplex /etc/opt/simplex-xftp /var/opt/simplex-xftp
run install -d -m 0750 -o simplex-ntf -g simplex-ntf /etc/opt/simplex-ntf /var/opt/simplex-ntf
# 0751 on /etc/hearth, not 0750: `turnserver` has to traverse it to reach its config in
# /etc/hearth/turn. `x` without `r` permits exactly that — walking a known path — and
# still hides the listing; every file inside keeps its own mode.
run install -d -m 0751 -o root    -g hearth  /etc/hearth
run install -d -m 0750 -o root    -g hearth  /etc/hearth/pki /etc/hearth/templates /etc/hearth/nftables
# Owned by `hearth`, not root: the daemon reads the relay passwords here to mint
# bundles, and WRITES turn-secret here on every rotation. That write is atomic
# (temp file + rename), so it needs permission on the directory itself — root:hearth
# 0750 fails with EACCES on `turn-secret.tmp.<pid>`, once every rotate_days.
# 0750 still shuts out everyone but root and the daemon.
run install -d -m 0750 -o hearth  -g hearth  /etc/hearth/secrets
run install -d -m 0750 -o hearth  -g hearth  /var/lib/hearth /var/opt/hearth /var/opt/hearth/backup
# The rendered coturn config lives here. Owner `hearth` renders it; group `turnserver`
# reads it; the setgid bit is what makes the rendered file land in that group instead
# of `hearth`. Both halves are required — see MODE_SHARED_SECRET in src/store.rs.
if id -u turnserver >/dev/null 2>&1; then
    run install -d -m 2750 -o hearth -g turnserver /etc/hearth/turn
else
    warn "no `turnserver` user yet — install coturn, then re-run this script (or fix-permissions.sh)"
fi
# systemd's credential store: the APNs key lives here, 0600 root:root, outside every
# backup path, and reaches ntf-server only through LoadCredential (docs/runbook-ntf.md).
run install -d -m 0700 -o root -g root /etc/credstore
# Каталог обновлений device_api (updates_dir по умолчанию). РОДИТЕЛЬ — root:root, и это
# не косметика: /srv лежит вне /etc и /var, а на fels этим каталогом владел обычный
# пользователь (fels:fels). Любой, кто вошёл под ним, мог подменить APK, который узел
# раздаёт телефонам, — обновление подписано, но каталог отдавал бы чужой файл.
# Сам updates — hearth:hearth: демон туда пишет.
run install -d -m 0755 -o root   -g root   /srv/hearth
run install -d -m 0750 -o hearth -g hearth /srv/hearth/updates
# Стикеры (stickers/import-telegram.py). Узел их только читает: владелец root, группе
# hearth — чтение, чтобы демон отдавал файлы, но не мог их подменить.
run install -d -m 0750 -o root -g hearth /srv/hearth/stickers

say "3. binaries"
# Журнал установки: что именно поставили и из чего это собрано.
#
# Раньше между «собрали» и «работает» не оставалось ни одной записи. В target/ за
# время работы накапливаются сборки разных коммитов и разных таргетов, скрипт брал
# первую попавшуюся, и вопрос «какой файл на узле» упирался в чужую память. Аудит это
# и нашёл: четыре найденных release-бинаря не совпали с установленными.
#
# Секретов здесь нет по построению (коммит, хеши, дата), поэтому 0644 root:hearth.
BUILD_LOG=/var/lib/hearth/installed.build-info

for binary in hearthd hearthctl; do
    MUSL="$HERE/../target/x86_64-unknown-linux-musl/release/$binary"
    NATIVE="$HERE/../target/release/$binary"
    # Два кандидата — это не «возьмём тот, что новее», а неизвестность: какой из них
    # собран из текущего дерева, скрипт знать не может. Молчаливый выбор первого и
    # приводил к расхождению установленного с собранным.
    if [[ -f "$MUSL" && -f "$NATIVE" ]]; then
        echo "   найдены ДВА кандидата на $binary:" >&2
        echo "     $MUSL" >&2
        echo "     $NATIVE" >&2
        echo "   Уберите лишний (rm) и повторите: ставить наугад нельзя." >&2
        exit 1
    fi
    SRC=""
    [[ -f "$MUSL"   ]] && SRC="$MUSL"
    [[ -f "$NATIVE" ]] && SRC="$NATIVE"
    if [[ -z "$SRC" ]]; then
        warn "$binary not built — run: cargo build --release --target x86_64-unknown-linux-musl"
        continue
    fi
    run install -m 0755 "$SRC" "/usr/local/bin/$binary"

    if [[ $DRY_RUN -eq 0 ]]; then
        # Паспорт спрашиваем у УСТАНОВЛЕННОГО файла, а не у исходного: доказывать надо
        # про то, что лежит на узле.
        if INFO="$("/usr/local/bin/$binary" build-info 2>/dev/null)"; then
            {
                echo "[$binary]"
                echo "installed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
                echo "installed_from=$SRC"
                echo "sha256=$(sha256sum "/usr/local/bin/$binary" | cut -d' ' -f1)"
                printf '%s\n' "$INFO"
                echo
            } >>"$BUILD_LOG"
            # Сборка из изменённого дерева не сопоставима с исходниками. Не отказ:
            # черновик на узле бывает нужен, а вот незамеченный черновик — нет.
            if printf '%s\n' "$INFO" | grep -q '^dirty=true$'; then
                warn "$binary собран из ИЗМЕНЁННОГО дерева (dirty=true)."
                warn "  Такую сборку нельзя сопоставить с коммитом. Для узла семьи"
                warn "  собирайте через deploy/build-reproducible.sh."
            fi
        else
            warn "$binary не назвал свой паспорт сборки (старая сборка?) — происхождение не записано"
        fi
    fi
done
if [[ $DRY_RUN -eq 0 && -f "$BUILD_LOG" ]]; then
    chown root:hearth "$BUILD_LOG"
    chmod 0644 "$BUILD_LOG"
    echo "   журнал установки: $BUILD_LOG"
fi
for binary in smp-server xftp-server; do
    [[ -x "/usr/local/bin/$binary" ]] || warn "/usr/local/bin/$binary is missing (copy the verified upstream release, ТЗ §6.1)"
done
# Optional: only nodes that serve push to the iOS app need it.
[[ -x /usr/local/bin/ntf-server ]] \
    || echo "   /usr/local/bin/ntf-server not installed — fine unless you enable [ntf] (docs/runbook-ntf.md)"
# The local alert channel referenced by alerts.beeper in hearthd.toml. Without it a
# critical alert has nowhere to go on a node that has no Gotify yet.
run install -m 0755 "$HERE/hearth-beep" /usr/local/sbin/hearth-beep

say "4. configuration"
if [[ -f /etc/hearth/hearthd.toml ]]; then
    echo "   /etc/hearth/hearthd.toml exists, left untouched"
else
    run install -m 0640 -o root -g hearth "$HERE/hearthd.toml" /etc/hearth/hearthd.toml
    warn "edit /etc/hearth/hearthd.toml: backup.recipients MUST be your real age public key"
fi
if [[ -f /etc/hearth/manifest.toml ]]; then
    echo "   /etc/hearth/manifest.toml exists, left untouched"
else
    run install -m 0640 -o root -g hearth "$HERE/../manifest.toml" /etc/hearth/manifest.toml
    warn "pin the real hashes: hearthctl manifest pin --name smp-server"
fi
run install -m 0640 -o root -g hearth "$HERE/coturn/turnserver.conf.tmpl" /etc/hearth/templates/turnserver.conf.tmpl

say "5. firewall (ТЗ §5.3)"
run install -m 0644 "$HERE/nftables/hearth.nft" /etc/hearth/nftables/hearth.nft
if [[ $DRY_RUN -eq 0 ]]; then
    nft -c -f /etc/hearth/nftables/hearth.nft && echo "   ruleset syntax ok"
fi
if ! grep -q 'hearth/nftables/hearth.nft' /etc/nftables.conf 2>/dev/null; then
    warn 'add to /etc/nftables.conf:  include "/etc/hearth/nftables/hearth.nft"'
fi

say "6. systemd units"
run install -m 0644 "$HERE/systemd/hearthd.service" /etc/systemd/system/hearthd.service
run install -m 0644 "$HERE/systemd/smp-server.service" /etc/systemd/system/smp-server.service
run install -m 0644 "$HERE/systemd/xftp-server.service" /etc/systemd/system/xftp-server.service
# Installed everywhere, enabled only where [ntf] is (docs/runbook-ntf.md). An installed
# but disabled unit costs nothing and keeps the node's units in step with the repo.
run install -m 0644 "$HERE/systemd/ntf-server.service" /etc/systemd/system/ntf-server.service
run install -m 0644 "$HERE/systemd/ntf-db-dump.service" /etc/systemd/system/ntf-db-dump.service
run install -m 0644 "$HERE/systemd/ntf-db-dump.timer" /etc/systemd/system/ntf-db-dump.timer
run install -d -m 0755 /etc/systemd/system/coturn.service.d
run install -m 0644 "$HERE/systemd/coturn.service.d-hearth.conf" /etc/systemd/system/coturn.service.d/hearth.conf
# Гейт режима узла (ADR 0013). Релейные юниты стартуют по WantedBy=multi-user.target
# при каждой загрузке — параллельно с hearthd и раньше, чем он прочитал node-mode.json.
# Без этого drop-in'а карантин снимался первой же перезагрузкой, а домашний узел
# перезагружается от любого сбоя питания.
#
# hearthctl не установлен — сюда мы уже не дойдём: проверка стоит на шаге 0, до любых
# изменений на узле. Здесь остаётся последняя сверка с УСТАНОВЛЕННЫМ файлом: между
# шагом 0 и этим местом его переписал шаг 3, и «install усёк цель, потому что кончилось
# место» — это ровно тот случай, когда гейт есть, а исполнить его нечем.
if [[ $DRY_RUN -eq 0 ]]; then
    if ! /usr/local/bin/hearthctl mode gate --file /nonexistent/hearth-gate-selftest.json \
        >/dev/null 2>&1; then
        echo "   hearthctl не установлен или не отвечает на гейт режима." >&2
        echo "   Проверьте вручную:" >&2
        echo "     hearthctl mode gate --file /nonexistent/x.json ; echo \$?   # ждём 0" >&2
        echo "   Пока это не исправлено, drop-in ставить нельзя: релеи не стартуют." >&2
        exit 1
    fi
fi
# Каталог состояния на отдельном разделе: drop-in обязан дождаться монтирования, иначе
# гейт не найдёт файла режима и молча разрешит старт релея в карантине. Поставочный
# путь в drop-in'е — /var/lib/hearth; если в hearthd.toml он другой, дописываем.
# `|| true`: при set -euo pipefail отсутствующий конфиг уронил бы установку целиком.
GATE_DROPIN="$HERE/systemd/relay.service.d-hearth-mode.conf"
STATE_DIR="$(sed -n 's/^[[:space:]]*state_dir[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    /etc/hearth/hearthd.toml 2>/dev/null | head -1 || true)"
if [[ -n "$STATE_DIR" && "$STATE_DIR" != "/var/lib/hearth" ]]; then
    GATE_DROPIN="$(mktemp)"
    trap 'rm -f "$GATE_DROPIN"' EXIT
    {
        cat "$HERE/systemd/relay.service.d-hearth-mode.conf"
        echo "# Дописано install.sh: paths.state_dir на этом узле нестандартный."
        echo "[Unit]"
        echo "RequiresMountsFor=$STATE_DIR"
    } >"$GATE_DROPIN"
    echo "   гейт ждёт монтирования $STATE_DIR"
fi
# Тот же drop-in — и самому демону. Поставочный hearthd.service ждёт /var/lib/hearth и
# /var/opt/hearth (RequiresMountsFor); если state_dir на этом узле другой и лежит на
# отдельном разделе, демон стартовал бы раньше монтирования и увидел пустой каталог:
# режим узла «потерян», журнал алертов начат заново, бэкап пишет мимо раздела.
if [[ -n "$STATE_DIR" && "$STATE_DIR" != "/var/lib/hearth" ]]; then
    run install -d -m 0755 /etc/systemd/system/hearthd.service.d
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "  would: write /etc/systemd/system/hearthd.service.d/state-dir.conf"
    else
        cat >/etc/systemd/system/hearthd.service.d/state-dir.conf <<EOF
# Дописано install.sh: paths.state_dir на этом узле нестандартный.
[Unit]
RequiresMountsFor=$STATE_DIR
EOF
        chmod 0644 /etc/systemd/system/hearthd.service.d/state-dir.conf
    fi
    echo "   hearthd ждёт монтирования $STATE_DIR"
fi
# Ставится и на ntf (он такой же релей), и на coturn: ADR 0013 обещает узел, который в
# карантине и переносе не обслуживает семью НИЧЕМ. Требуется systemd 243+
# (ExecCondition); на Debian 12 это 252.
for unit in smp-server xftp-server ntf-server; do
    run install -d -m 0755 "/etc/systemd/system/$unit.service.d"
    run install -m 0644 "$GATE_DROPIN" \
        "/etc/systemd/system/$unit.service.d/hearth-mode.conf"
done
run install -m 0644 "$GATE_DROPIN" \
    /etc/systemd/system/coturn.service.d/hearth-mode.conf
# /run is tmpfs and the Debian package creates neither directory. Without them systemd
# fails the unit at step NAMESPACE (status=226) before turnserver even runs, because
# ReadWritePaths cannot bind a path that does not exist.
run install -d -m 0755 /etc/tmpfiles.d
run install -m 0644 "$HERE/tmpfiles/hearth-coturn.conf" /etc/tmpfiles.d/hearth-coturn.conf
run systemd-tmpfiles --create /etc/tmpfiles.d/hearth-coturn.conf
run systemctl daemon-reload

say "7. polkit: let hearthd manage the relay units"
# hearthd runs unprivileged, and polkit rejects `systemctl restart/stop` of system
# units from a non-root user by default. Without this rule the supervisor, the TURN
# rotation, the migration export and the integrity stop all fail silently.
# The rule lists exactly the relay units and coturn — nothing else, and no enable/disable.
run install -d -m 0755 /etc/polkit-1/rules.d
run install -m 0644 "$HERE/polkit/49-hearthd.rules" /etc/polkit-1/rules.d/49-hearthd.rules

say "8. host hardening (ТЗ §5.2, §11)"
# No resolver: the node resolves nothing, so nothing can be poisoned. (ntf-server, when
# enabled, gets a private resolv.conf of its own — the host still has none.)
if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
    warn "systemd-resolved is enabled — disable it (ТЗ §5.2)"
fi
# No unattended upgrades: the node has no egress, and a surprise restart is an outage.
if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    warn "unattended-upgrades is enabled — disable it (ТЗ §11)"
fi
# Парольный вход по ssh. У всех, кому нужен узел, есть ключи; пароль — лишний способ
# подобрать вход в машину, которая держит релеи семьи. Проверяем действующую настройку
# (sshd -T), а не файл: значение может прийти из любого файла в sshd_config.d.
if command -v sshd >/dev/null 2>&1 && sshd -T 2>/dev/null | grep -qi '^passwordauthentication yes'; then
    warn 'ssh: PasswordAuthentication yes — закрыть (/etc/ssh/sshd_config.d/99-server.conf) и systemctl reload ssh'
fi
# Автовход на учётку с sudo. Проверка добавлена после аудита 18.09.2026: на fels
# автологин GDM приземлился на пользователя с `NOPASSWD: ALL`, и ни одна проверка
# этого не заметила — install.sh смотрел на resolved, unattended-upgrades и sshd, но
# не на то, кто сидит за клавиатурой. Десять секунд у телевизора = ключ CA релея.
if [[ -f /etc/gdm3/daemon.conf ]] \
   && grep -qiE '^[[:space:]]*AutomaticLoginEnable[[:space:]]*=[[:space:]]*(true|1|yes)' /etc/gdm3/daemon.conf; then
    # `|| true` обязателен: скрипт под `set -e -o pipefail`, а grep без совпадения
    # роняет весь конвейер — то есть отсутствие строки AutomaticLogin прерывало бы
    # установку на предупреждающей проверке.
    AUTOLOGIN_USER="$(grep -E '^[[:space:]]*AutomaticLogin[[:space:]]*=' /etc/gdm3/daemon.conf \
                      | head -1 | cut -d= -f2- | tr -d '[:space:]' || true)"
    if [[ -n "$AUTOLOGIN_USER" ]] \
       && id -nG "$AUTOLOGIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then
        warn "автовход GDM на пользователя '$AUTOLOGIN_USER', который состоит в sudo —"
        warn "  открытая сессия у телевизора равна root-шеллу. docs/runbook-host-hardening.md §1.2, §2.1"
    fi
fi
# NOPASSWD у человека. Демону sudo не нужен вовсе: hearthd работает от `hearth` с
# CAP_NET_ADMIN и правилом polkit выше, поэтому «список команд для демона» здесь не
# при чём — правило NOPASSWD принадлежит человеку и отменяет пароль как барьер.
if command -v sudo >/dev/null 2>&1 && [[ $(id -u) -eq 0 ]]; then
    while read -r u; do
        [[ -n "$u" ]] || continue
        if sudo -n -l -U "$u" 2>/dev/null | grep -q 'NOPASSWD'; then
            warn "у интерактивного пользователя '$u' есть правило NOPASSWD — sudo не спросит пароль"
            warn "  ни у него, ни у того, кто подошёл к его сессии. docs/runbook-host-hardening.md §1.2"
        fi
    done < <(awk -F: '$3 >= 1000 && $3 < 65000 && $7 !~ /(nologin|false|sync)$/ {print $1}' /etc/passwd)
fi
# Sleep would silently stop message delivery.
run systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

say "10. пин своих бинарников"
# Раньше это была подсказка в финальном тексте, и пропущенный шаг оставлял в манифесте
# нулевой плейсхолдер — то есть проверку целостности, которая валит узел в карантин
# при первом же обходе. Пин своих файлов — не решение человека: измеряется ровно то,
# что этот же скрипт только что положил, а происхождение hearthctl берёт у самого
# файла (`build-info`). Решение человека — пин upstream-бинарей, и оно остаётся ниже.
if [[ $DRY_RUN -eq 0 ]]; then
    for binary in hearthd hearthctl; do
        [[ -x "/usr/local/bin/$binary" ]] || continue
        if ! grep -q "name = \"$binary\"" /etc/hearth/manifest.toml 2>/dev/null; then
            echo "   в манифесте нет записи $binary — пропускаю"
            continue
        fi
        hearthctl manifest pin --name "$binary" \
            || warn "не удалось запинить $binary — сделайте это руками, иначе узел уйдёт в карантин"
    done
else
    echo "  would run: hearthctl manifest pin --name hearthd"
fi

cat <<'NEXT'

== remaining steps (each needs a decision, so the script stops here)

  1. Relay init (once, ТЗ §6.2/§6.3) — see relays/README.md:
       NODE_HOST=<ваш домен> ./relays/smp/init-smp.sh
       NODE_HOST=<ваш домен> ./relays/xftp/init-xftp.sh
     The init scripts write the passwords to /etc/hearth/secrets and hand them to the
     `hearth` group; they also chown the relay directories. Run `fix-permissions.sh`
     afterwards if you ever init by hand instead.

  2. Pin the UPSTREAM binaries you verified (ТЗ §6.1) — своих скрипт уже запинил:
       hearthctl manifest pin --name smp-server  --version <tag>
       hearthctl manifest pin --name xftp-server --version <tag>
       hearthctl manifest pin --name turnserver  --version distro
     turnserver НЕ забыть: запись о нём есть в поставочном манифесте, и пока в ней
     нулевой плейсхолдер, узел не может подтвердить, что на нём работает, — надзор не
     будет поднимать релеи сам и раз в час напомнит алертом. Проверить, что нулей не
     осталось (закомментированный блок ntf-server в счёт не идёт):
       grep -n 'sha256 = "0\{64\}"' /etc/hearth/manifest.toml   # ждём одну строку:
     Проверить, что происхождение записано:
       grep -A6 'name = "hearthd"' /etc/hearth/manifest.toml
       cat /var/lib/hearth/installed.build-info

  3. Admin PKI (ТЗ §7.3), as root:
       hearthd ca init
       hearthd ca issue owner          # move owner.key to the admin workstation
     Then hand the server key to the daemon (ca init runs as root, hearthd does not):
       ./deploy/fix-permissions.sh

  4. TURN secret:
       hearthctl rotate turn-secret    # renders /etc/turnserver.conf

  5. Start:
       nft -f /etc/hearth/nftables/hearth.nft
       systemctl enable --now smp-server xftp-server coturn hearthd
       hearthctl health

     Если узел в карантине, переносе или обслуживании, `systemctl start` релея НИЧЕГО
     не поднимет: гейт режима пометит юнит пропущенным (в журнале — condition failed,
     причина рядом). Так и задумано. Посмотреть режим и снять его:
       hearthctl mode gate ; echo $?          # путь берётся из hearthd.toml
       hearthctl mode clear                   # через работающий hearthd, с сертификатом
       sudo hearthctl mode clear --local      # НА УЗЛЕ: без hearthd и без сертификата

     Второй вариант — аварийный выход, и он существует именно для случая «hearthd не
     поднимается, а релеи заблокированы»: docs/runbook-node-mode.md.

  6. Run the acceptance tests: tests/acceptance/run-all.sh
     They now check ownership, not just file modes — the mismatch that used to break
     bundles and backups silently.

  7. Optional — push server for the iOS app (ADR 0016): docs/runbook-ntf.md.
     It adds PostgreSQL, a public port and the relay stack's first way out (to Apple);
     skip it unless the iOS app is in use.

== not installed by this script (host-specific, decide per node)

  * deploy/systemd/var-opt-*.mount — put the relay data on a roomy partition. On a
    host where /var is small this is not optional: the store log grows without bound.
    NB the xftp and ntf units deploy under their systemd-escaped names, see the headers.
  * /etc/nftables.conf — deploy/nftables/nftables.conf. The Debian default starts with
    `flush ruleset`, which deletes Docker's tables too; on a host that runs containers
    that costs them the network on every boot, with nothing in any log.
  * deploy/monitoring/ — Prometheus, node_exporter, Alertmanager and the local alert
    sink. See deploy/monitoring/README.md.

NEXT
