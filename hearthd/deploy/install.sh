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

say "1. users"
# System users, no shell, no home. The relays and hearthd never need to log in.
id -u simplex >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin simplex
id -u hearth  >/dev/null 2>&1 || run useradd --system --no-create-home --shell /usr/sbin/nologin hearth

say "2. directories (ТЗ §10.1: everything the node owns lives in these)"
run install -d -m 0750 -o simplex -g simplex /etc/opt/simplex /var/opt/simplex
run install -d -m 0750 -o simplex -g simplex /etc/opt/simplex-xftp /var/opt/simplex-xftp
run install -d -m 0750 -o root    -g hearth  /etc/hearth /etc/hearth/pki /etc/hearth/templates /etc/hearth/nftables
run install -d -m 0700 -o root    -g hearth  /etc/hearth/secrets
run install -d -m 0750 -o hearth  -g hearth  /var/lib/hearth /var/opt/hearth /var/opt/hearth/backup

say "3. binaries"
for binary in hearthd hearthctl; do
    if [[ -f "$HERE/../target/x86_64-unknown-linux-musl/release/$binary" ]]; then
        run install -m 0755 "$HERE/../target/x86_64-unknown-linux-musl/release/$binary" "/usr/local/bin/$binary"
    elif [[ -f "$HERE/../target/release/$binary" ]]; then
        run install -m 0755 "$HERE/../target/release/$binary" "/usr/local/bin/$binary"
    else
        warn "$binary not built — run: cargo build --release --target x86_64-unknown-linux-musl"
    fi
done
for binary in smp-server xftp-server; do
    [[ -x "/usr/local/bin/$binary" ]] || warn "/usr/local/bin/$binary is missing (copy the verified upstream release, ТЗ §6.1)"
done

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
run install -d -m 0755 /etc/systemd/system/coturn.service.d
run install -m 0644 "$HERE/systemd/coturn.service.d-hearth.conf" /etc/systemd/system/coturn.service.d/hearth.conf
run systemctl daemon-reload

say "7. host hardening (ТЗ §5.2, §11)"
# No resolver: the node resolves nothing, so nothing can be poisoned.
if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
    warn "systemd-resolved is enabled — disable it (ТЗ §5.2)"
fi
# No unattended upgrades: the node has no egress, and a surprise restart is an outage.
if systemctl is-enabled unattended-upgrades >/dev/null 2>&1; then
    warn "unattended-upgrades is enabled — disable it (ТЗ §11)"
fi
# Sleep would silently stop message delivery.
run systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

cat <<'NEXT'

== remaining steps (each needs a decision, so the script stops here)

  1. Relay init (once, ТЗ §6.2/§6.3) — see relays/README.md:
       NODE_HOST=<ваш домен> ./relays/smp/init-smp.sh
       xftp-server init ...
     Then copy the passwords into /etc/hearth/secrets/{smp,xftp}-create-password (0600).

  2. Pin the binaries you verified (ТЗ §6.1):
       hearthctl manifest pin --name smp-server  --version <tag>
       hearthctl manifest pin --name xftp-server --version <tag>
       hearthctl manifest pin --name hearthd     --version 0.1.0

  3. Admin PKI (ТЗ §7.3):
       hearthd ca init
       hearthd ca issue owner          # move owner.key to the admin workstation

  4. TURN secret:
       hearthctl rotate turn-secret    # renders /etc/turnserver.conf

  5. Start:
       nft -f /etc/hearth/nftables/hearth.nft
       systemctl enable --now smp-server xftp-server coturn hearthd
       hearthctl health

  6. Run the acceptance tests: tests/acceptance/run-all.sh

NEXT
