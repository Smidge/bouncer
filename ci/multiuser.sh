#!/bin/sh
# Dedicated-user mode, end to end, on Linux. Run as root:
#
#   sudo ci/multiuser.sh target/release/bouncer [systemd|direct]
#
# systemd: installs contrib/bouncer.service (key in an encrypted systemd credential).
# direct:  runs `bouncer serve` as root in the background (key in a file), e.g. in a container.
#
# Then checks that the daemon dropped to the bouncer user with no capabilities, that an
# `agent` user can fetch a secret and is attributed across uids, and that the agent cannot
# read the vault, key or log, change secrets, or be fooled by a socket it planted.
set -eu

BIN=${1:-target/release/bouncer}
MODE=${2:-systemd}
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

install -m 0755 "$BIN" /usr/local/bin/bouncer
id bouncer >/dev/null 2>&1 || useradd --system --home-dir /var/lib/bouncer --shell /usr/sbin/nologin bouncer
getent group bouncer-clients >/dev/null || groupadd bouncer-clients
id agent >/dev/null 2>&1 || useradd --create-home --shell /bin/sh agent
usermod -aG bouncer-clients agent
install -d -o bouncer -g bouncer -m 0700 /var/lib/bouncer
install -d -m 0755 /etc/bouncer
AGENT_UID=$(id -u agent)
BOUNCER_UID=$(id -u bouncer)

if [ "$MODE" = systemd ]; then
    KEYLINE='key_credential = "bouncer-key"'
else
    KEYLINE='key = "/var/lib/bouncer/key"'
fi
cat > /etc/bouncer/config.toml <<EOF
user = "bouncer"
socket = "/run/bouncer/bouncer.sock"
socket_mode = "0660"
socket_group = "bouncer-clients"
admin_socket = "/run/bouncer/admin.sock"
allowed_uids = [$AGENT_UID]
server_uid = $BOUNCER_UID
vault = "/var/lib/bouncer/vault.bin"
audit_log = "/var/lib/bouncer/audit.jsonl"
$KEYLINE
context_vars = ["AGENT_THREAD"]
EOF
chmod 0644 /etc/bouncer/config.toml
export BOUNCER_CONFIG=/etc/bouncer/config.toml

if [ "$MODE" = systemd ]; then
    install -d -m 0700 /etc/credstore.encrypted
    bouncer keygen | systemd-creds encrypt --name=bouncer-key - /etc/credstore.encrypted/bouncer-key
    systemd-run --quiet --pipe --wait -p User=bouncer \
        -p LoadCredentialEncrypted=bouncer-key:/etc/credstore.encrypted/bouncer-key \
        -E BOUNCER_CONFIG=$BOUNCER_CONFIG /usr/local/bin/bouncer init
    install -m 0644 contrib/bouncer.service /etc/systemd/system/bouncer.service
    systemctl daemon-reload
    systemctl start bouncer || { journalctl -u bouncer --no-pager | tail -50; fail "service did not start"; }
    [ ! -e /var/lib/bouncer/key ] || fail "a key file exists on disk in credential mode"
else
    su -s /bin/sh bouncer -c "BOUNCER_CONFIG=$BOUNCER_CONFIG bouncer init" >/dev/null
    bouncer serve 2>/tmp/bouncer-serve.log &
fi
for i in $(seq 50); do [ -S /run/bouncer/bouncer.sock ] && break; sleep 0.1; done
[ -S /run/bouncer/bouncer.sock ] || { cat /tmp/bouncer-serve.log 2>/dev/null; journalctl -u bouncer --no-pager 2>/dev/null | tail -30; fail "no socket"; }
ok "daemon started ($MODE)"

# Privileges: the daemon runs as bouncer with no capabilities; the helper keeps exactly two.
for pid in $(pgrep -x bouncer); do
    uid=$(awk '/^Uid:/ {print $2}' /proc/$pid/status)
    capeff=$(awk '/^CapEff:/ {print $2}' /proc/$pid/status)
    capbnd=$(awk '/^CapBnd:/ {print $2}' /proc/$pid/status)
    [ "$uid" = "$BOUNCER_UID" ] || fail "pid $pid runs as uid $uid"
    case "$capeff" in
        0000000000000000) ok "pid $pid: uid $uid, no capabilities" ;;
        0000000000080004) [ "$capbnd" = 0000000000080004 ] || fail "helper bounding set $capbnd"
                          ok "pid $pid: uid $uid, attribution helper with CAP_DAC_READ_SEARCH+CAP_SYS_PTRACE only" ;;
        *) fail "pid $pid has capabilities $capeff" ;;
    esac
done
[ "$(pgrep -x bouncer | wc -l)" -eq 2 ] || { ps -eo pid,uid,comm,args; cat /tmp/bouncer-serve.log 2>/dev/null; fail "expected the daemon and its helper"; }

# An admin (the bouncer user, on the admin socket) stores a secret.
printf %s fake-multiuser-value | su -s /bin/sh bouncer -c \
    "BOUNCER_CONFIG=$BOUNCER_CONFIG bouncer --socket /run/bouncer/admin.sock set DEMO --desc demo"
ok "admin set over the admin socket"

as_agent() { su -s /bin/sh agent -c "BOUNCER_CONFIG=$BOUNCER_CONFIG AGENT_THREAD=thread-42 $*"; }

v=$(as_agent "bouncer get DEMO --reason 'multi-user CI check'")
[ "$v" = fake-multiuser-value ] || fail "agent got '$v'"
ok "agent fetched the secret"

# Cross-uid attribution: the agent's environment was read by the helper.
last=$(tail -n 1 /var/lib/bouncer/audit.jsonl)
echo "$last" | grep -q "\"AGENT_THREAD\":{\"value\":\"thread-42\"" || fail "no cross-uid context: $last"
echo "$last" | grep -q "\"status\":\"ok\"" || fail "attribution not ok: $last"
echo "$last" | grep -q "\"uid\":$AGENT_UID" || fail "peer uid missing: $last"
ok "attribution across uids (context var read from the agent's process)"

# The agent cannot read or list the daemon's files.
for f in /var/lib/bouncer/vault.bin /var/lib/bouncer/audit.jsonl /var/lib/bouncer/key /var/lib/bouncer; do
    if su -s /bin/sh agent -c "cat $f >/dev/null 2>&1 || ls $f >/dev/null 2>&1"; then
        fail "agent can read $f"
    fi
done
ok "agent cannot read the vault, key or audit log"

for pid in $(pgrep -x bouncer); do
    if su -s /bin/sh agent -c "cat /proc/$pid/environ >/dev/null 2>&1 || cat /proc/$pid/maps >/dev/null 2>&1"; then
        fail "agent can inspect daemon pid $pid"
    fi
done
ok "agent cannot inspect the daemon's processes"

# The agent cannot change secrets: not an admin, and not on the admin socket.
set +e
printf x | as_agent "bouncer set EVIL" 2>/dev/null; rc=$?
[ $rc -eq 3 ] || fail "agent set exited $rc, expected 3 (denied)"
printf x | as_agent "bouncer --socket /run/bouncer/admin.sock set EVIL" 2>/dev/null; rc=$?
[ $rc -eq 5 ] || fail "agent reaching the admin socket exited $rc, expected 5"
set -e
ok "agent cannot change secrets"

# A socket the agent planted is refused by clients that expect the bouncer uid.
if command -v python3 >/dev/null; then
    su -s /bin/sh agent -c "python3 -c \"
import os, socket, time
s = socket.socket(socket.AF_UNIX); s.bind('/tmp/fake-bouncer.sock'); os.chmod('/tmp/fake-bouncer.sock', 0o777)
s.listen(5); time.sleep(20)\"" &
    for i in $(seq 50); do [ -S /tmp/fake-bouncer.sock ] && break; sleep 0.1; done
    set +e
    printf x | su -s /bin/sh bouncer -c "BOUNCER_CONFIG=$BOUNCER_CONFIG bouncer --socket /tmp/fake-bouncer.sock set LEAK" 2>/tmp/fake.err; rc=$?
    set -e
    [ $rc -eq 6 ] || fail "client talked to a planted socket (exit $rc): $(cat /tmp/fake.err)"
    ok "client refuses a socket owned by another uid"
fi

su -s /bin/sh bouncer -c "BOUNCER_CONFIG=$BOUNCER_CONFIG bouncer --socket /run/bouncer/admin.sock verify-log --daemon"
ok "audit log verifies (keyed, by the daemon)"
echo "all multi-user checks passed"
