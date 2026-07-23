#!/usr/bin/env bash
# Classic-VPN live verification, part 3: RECONNECT / always-on supervisor.
#
# Proves the reliability loop is live: when the tunnel can't come up (the server is
# unreachable), the client's supervisor detects the dead link, backs off, and RETRIES —
# instead of silently giving up. (Failover to a *different* server is the same code path,
# unit-tested; here we watch the loop itself run against a deliberately-dead endpoint.)
#
# Topology — two namespaces:
#   oxide-cli --10.70.0.0/24-- oxide-cp   (control plane; also the client's default gw)
#     .2                        .1
# A "ghost" server is registered with an UNREACHABLE endpoint (10.99.99.99), so every
# connect attempt times out and the supervisor loops.
#
# Requires root.  Run:  sudo bash scripts/netns-reconnect-test.sh
set -euo pipefail

CLI=oxide-cli
CP=oxide-cp
DIR=$(mktemp -d)
BIN=target/debug
RUN_SECS=${RUN_SECS:-46} # long enough for ~2 connect-timeout (20s) + backoff cycles

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

echo "== namespaces + veth =="
for ns in "$CLI" "$CP"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$CP"
ip link add veth-cli netns "$CLI" type veth peer name veth-cp netns "$CP"
ip -n "$CLI" addr add 10.70.0.2/24 dev veth-cli
ip -n "$CP"  addr add 10.70.0.1/24 dev veth-cp
ip -n "$CLI" link set lo up; ip -n "$CP" link set lo up
ip -n "$CLI" link set veth-cli up
ip -n "$CP"  link set veth-cp up
ip -n "$CLI" route add default via 10.70.0.1   # a gateway to pin the endpoint against

echo "== control plane (in oxide-cp), + a 'ghost' server with an unreachable endpoint =="
# Register the ghost with NO --dns so the client doesn't touch /etc/resolv.conf (a namespace
# shares the host's mount). Its endpoint 10.99.99.99 is a black hole → connects never complete.
GKEY=$("$SERVERD" genkey | "$SERVERD" pubkey)
ip netns exec "$CP" "$CP_BIN" --db "$DB" add-server \
    --id ghost --public-key "$GKEY" --endpoint 10.99.99.99:51820 --cidr 10.8.0.0/24 >/dev/null
ip netns exec "$CP" env RUST_LOG=warn "$CP_BIN" --db "$DB" serve --listen 10.70.0.1:8080 >"$DIR/cp.log" 2>&1 &
CP_PID=$!
sleep 1

echo "== create an account =="
ACCT=$(ip netns exec "$CLI" "$CLIENT" account --control-plane "$CPURL" | tr -dc '0-9')
echo "  account: ${ACCT:0:4}…"

echo "== connect (always-on) — this will keep retrying the dead 'ghost' for ${RUN_SECS}s =="
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" connect \
    --control-plane "$CPURL" --account "$ACCT" --server ghost >"$DIR/cli.log" 2>&1 &
CLI_PID=$!
sleep "$RUN_SECS"
kill "$CLI_PID" 2>/dev/null; CLI_PID=""

echo
echo "== what the supervisor did (client log) =="
grep -E "selecting a server|connecting server|link dropped; reconnecting" "$DIR/cli.log" | sed 's/^/  /' || true

# Count unambiguous messages: one "selecting a server" per loop iteration, one
# "link dropped" per detected dead link.
ITERS=$(grep -c "selecting a server" "$DIR/cli.log" || true)
RECON=$(grep -c "link dropped" "$DIR/cli.log" || true)
echo
echo "  loop iterations (selecting): $ITERS    dead-link detections (reconnecting): $RECON"
if [ "$ITERS" -ge 2 ] && [ "$RECON" -ge 1 ]; then
    echo
    echo "RESULT: PASS ✓  the always-on supervisor detected the dead link and kept reconnecting (with backoff)."
    exit 0
else
    echo "== full client log =="; cat "$DIR/cli.log"
    echo "== control-plane log =="; cat "$DIR/cp.log"
    echo
    echo "RESULT: FAIL ✗  (expected >=2 connect attempts and >=1 reconnect; see logs)"
    exit 1
fi
