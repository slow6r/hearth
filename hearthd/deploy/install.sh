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
# Sleep would silently stop message delivery.
run systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

cat <<'NEXT'

== remaining steps (each needs a decision, so the script stops here)

  1. Relay init (once, ТЗ §6.2/§6.3) — see relays/README.md:
       NODE_HOST=<ваш домен> ./relays/smp/init-smp.sh
       NODE_HOST=<ваш домен> ./relays/xftp/init-xftp.sh
     The init scripts write the passwords to /etc/hearth/secrets and hand them to the
     `hearth` group; they also chown the relay directories. Run `fix-permissions.sh`
     afterwards if you ever init by hand instead.

  2. Pin the binaries you verified (ТЗ §6.1):
       hearthctl manifest pin --name smp-server  --version <tag>
       hearthctl manifest pin --name xftp-server --version <tag>
       hearthctl manifest pin --name hearthd     --version 0.1.0

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
