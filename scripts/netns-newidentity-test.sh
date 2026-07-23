#!/usr/bin/env bash
# 3E "new identity" live verification: one action -> fresh device key + reconnect to a
# DIFFERENT exit (Tor-style "new circuit"), for per-session unlinkability.
#
# Reuses the reconnect harness topology (client + control plane in two namespaces) but
# registers TWO ghost exits. The client connects with auto-select (lands on one), then we
# send SIGUSR1 (the CLI's "new identity" trigger). We assert:
#   * the device key file CHANGED (fresh, unlinkable identity), and
#   * the client reconnects to the OTHER exit (the just-left one is excluded).
#
# The ghosts have unreachable endpoints, so tunnels never actually come up — that's fine:
# run_supervised installs routing and emits "connecting server=<id>" before the (doomed)
# handshake, and SIGUSR1 tears the attempt down regardless. We keep the whole run well under
# the 20s connect_timeout so the exit switch can ONLY be the new-identity action, never a
# natural link-dead failover.
#
# Requires root.  Run:  sudo bash scripts/netns-newidentity-test.sh
set -euo pipefail

CLI=oxide-cli
CP=oxide-cp
DIR=$(mktemp -d)
BIN=target/debug

cleanup() {
    set +e
    [ -n "${CP_PID:-}" ] && kill "$CP_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$CP" 2>/dev/null
    rm -rf "$DIR"
}
trap cleanup EXIT

if [ -z "${OXIDE_SKIP_BUILD:-}" ]; then
    echo "== building =="
    ( . "$HOME/.cargo/env" 2>/dev/null; cargo build -p oxide-serverd -p oxide-client -p oxide-control-plane )
fi
SERVERD="$PWD/$BIN/oxide-serverd"
CLIENT="$PWD/$BIN/oxide-client"
CP_BIN="$PWD/$BIN/oxide-control-plane"
DB="$DIR/cp.db"
CPURL="http://10.70.0.1:8080"
KEYFILE="$DIR/device.key"

echo "== namespaces + veth =="
for ns in "$CLI" "$CP"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$CP"
ip link add veth-cli netns "$CLI" type veth peer name veth-cp netns "$CP"
ip -n "$CLI" addr add 10.70.0.2/24 dev veth-cli
ip -n "$CP"  addr add 10.70.0.1/24 dev veth-cp
ip -n "$CLI" link set lo up; ip -n "$CP" link set lo up
ip -n "$CLI" link set veth-cli up
ip -n "$CP"  link set veth-cp up
ip -n "$CLI" route add default via 10.70.0.1   # a gateway to pin endpoints against

echo "== control plane + TWO ghost exits (both auto-selectable; never-heartbeated => healthy) =="
GA=$("$SERVERD" genkey | "$SERVERD" pubkey)
GB=$("$SERVERD" genkey | "$SERVERD" pubkey)
ip netns exec "$CP" "$CP_BIN" --db "$DB" add-server \
    --id ghost-a --public-key "$GA" --endpoint 10.99.99.1:51820 --cidr 10.8.0.0/24 >/dev/null
ip netns exec "$CP" "$CP_BIN" --db "$DB" add-server \
    --id ghost-b --public-key "$GB" --endpoint 10.99.99.2:51820 --cidr 10.8.0.0/24 >/dev/null
ip netns exec "$CP" env RUST_LOG=warn "$CP_BIN" --db "$DB" serve --listen 10.70.0.1:8080 >"$DIR/cp.log" 2>&1 &
CP_PID=$!
sleep 1

echo "== create an account =="
ACCT=$(ip netns exec "$CLI" "$CLIENT" account --control-plane "$CPURL" | tr -dc '0-9')
echo "  account: ${ACCT:0:4}…"

echo "== connect (auto-select, always-on) =="
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" connect \
    --control-plane "$CPURL" --account "$ACCT" --key-file "$KEYFILE" >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

# Helper: first exit id in a stream of connecting lines (empty if none; never fails set -e).
# tracing colours the `server=` field with ANSI escapes, so strip them before matching.
exit_from() {
    sed -E 's/\x1b\[[0-9;]*m//g' \
        | grep -oE 'connecting server=Some\("[^"]+"\)' | head -1 \
        | grep -oE '"[^"]+"' | tr -d '"'
}

sleep 5   # let it select + start attempting the first exit (well under connect_timeout=20s)
KEY_BEFORE=$(cat "$KEYFILE" 2>/dev/null || true)
FIRST=$(exit_from <"$DIR/cli.log" || true)
echo "  first exit: ${FIRST:-<none>}   key(before)=${KEY_BEFORE:0:12}…"

echo "== send SIGUSR1 = new identity =="
kill -USR1 "$CLI_PID"
sleep 5   # rotate key + re-select; still under connect_timeout so no natural failover

KEY_AFTER=$(cat "$KEYFILE" 2>/dev/null || true)
# The exit chosen AFTER the new-identity marker.
SECOND=$(awk '/new identity/{f=1} f' "$DIR/cli.log" | exit_from || true)
echo "  second exit: ${SECOND:-<none>}   key(after)=${KEY_AFTER:0:12}…"

kill "$CLI_PID" 2>/dev/null || true; CLI_PID=""
cp "$DIR/cli.log" /tmp/oxide-newidentity-cli.log 2>/dev/null || true

RC=0
echo
echo "== assertions =="
if grep -q "new identity" "$DIR/cli.log"; then
    echo "  new-identity action fired: PASS ✓"
else
    echo "  new-identity action fired: FAIL ✗"; RC=1
fi
if [ -n "$KEY_BEFORE" ] && [ -n "$KEY_AFTER" ] && [ "$KEY_BEFORE" != "$KEY_AFTER" ]; then
    echo "  device key rotated (unlinkable): PASS ✓"
else
    echo "  device key rotated: FAIL ✗  (before='${KEY_BEFORE:0:12}' after='${KEY_AFTER:0:12}')"; RC=1
fi
if [ -n "$FIRST" ] && [ -n "$SECOND" ] && [ "$FIRST" != "$SECOND" ]; then
    echo "  reconnected to a DIFFERENT exit ($FIRST -> $SECOND): PASS ✓"
else
    echo "  reconnected to a different exit: FAIL ✗  (first='$FIRST' second='$SECOND')"; RC=1
fi

if [ $RC -ne 0 ]; then
    echo "== client log (also /tmp/oxide-newidentity-cli.log) =="; cat "$DIR/cli.log"
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  new identity = fresh device key + a different exit."
else
    echo "RESULT: FAIL ✗  (see log above)"
fi
exit $RC
