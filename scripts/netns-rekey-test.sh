#!/usr/bin/env bash
# 4B continuous rekey live verification: rotate the post-quantum PSK on a LIVE tunnel and prove
# traffic survives, end to end through the control plane.
#
# Topology — two network namespaces on one host:
#
#   oxide-cli --10.50.0.0/24-- oxide-srv
#      .2                       .1
#   client tunnel 10.8.0.2      server tunnel 10.8.0.1
#                               + control plane (10.50.0.1:8080)
#                               + oxide-serverd (PQ, CP-polling)
#
# Flow: the control plane + a REAL PQ server run in oxide-srv; the client `connect`s via the CP
# with `--rekey-secs`. Every interval the client re-encapsulates to the server's ML-KEM key,
# re-registers the fresh ciphertext, and swaps the peer's PSK in place; the server picks up the
# new ciphertext on its next poll and rotates its side. We assert:
#   * the tunnel works before AND after several rotations (traffic survives the PSK swap), and
#   * both logs show the rotation happening (client "rotated the post-quantum PSK",
#     server "rotating PSK for a peer").
#
# NOTE: authored on a Linux box WITHOUT root; NOT run by its author. Run it on a real host to
# confirm the live poll-window convergence.  Requires root (CAP_NET_ADMIN).
#   sudo bash scripts/netns-rekey-test.sh
set -euo pipefail

CLI=oxide-cli
SRV=oxide-srv
DIR=$(mktemp -d)
BIN=target/debug

cleanup() {
    set +e
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CP_PID:-}" ] && kill "$CP_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$SRV" 2>/dev/null
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
CPURL="http://10.50.0.1:8080"
KEYFILE="$DIR/device.key"

echo "== keys (server WG + server ML-KEM) =="
SPRIV=$("$SERVERD" genkey); SPUB=$(echo "$SPRIV" | "$SERVERD" pubkey)
# pq-genkey prints two labelled lines; pull the base64 off each.
PQOUT=$("$SERVERD" pq-genkey)
PQSEED=$(echo "$PQOUT" | awk '/pq_private_seed/{print $NF}')
PQPUB=$(echo  "$PQOUT" | awk '/pq_public_key/{print $NF}')

echo "== namespaces + veth (client <-> server underlay; CP lives in the server ns) =="
for ns in "$CLI" "$SRV"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$SRV"
ip link add veth-cs netns "$CLI" type veth peer name veth-sc netns "$SRV"
ip -n "$CLI" addr add 10.50.0.2/24 dev veth-cs
ip -n "$SRV" addr add 10.50.0.1/24 dev veth-sc
ip -n "$CLI" link set lo up; ip -n "$SRV" link set lo up
ip -n "$CLI" link set veth-cs up; ip -n "$SRV" link set veth-sc up

echo "== control plane + register the PQ server (prints its auth token) =="
ip netns exec "$SRV" "$CP_BIN" --db "$DB" add-server \
    --id srv-pq --public-key "$SPUB" --endpoint 10.50.0.1:51820 --cidr 10.8.0.0/24 \
    --pq-public-key "$PQPUB" >"$DIR/add.log"
TOKEN=$(awk '/auth_token:/{print $NF}' "$DIR/add.log")
ip netns exec "$SRV" env RUST_LOG=warn "$CP_BIN" --db "$DB" serve --listen 10.50.0.1:8080 \
    >"$DIR/cp.log" 2>&1 &
CP_PID=$!
sleep 1

echo "== server config: PQ + CP-polling (peers come from the control plane, fast poll) =="
cat > "$DIR/server.toml" <<EOF
[interface]
private_key = "$SPRIV"
address = "10.8.0.1/24"
listen_port = 51820
pq_private_seed = "$PQSEED"
[control_plane]
url = "http://10.50.0.1:8080"
server_id = "srv-pq"
token = "$TOKEN"
poll_interval_secs = 2
EOF
ip netns exec "$SRV" env RUST_LOG=info "$SERVERD" up --config "$DIR/server.toml" >"$DIR/srv.log" 2>&1 &
SRV_PID=$!
sleep 1

echo "== account + connect with a short rekey interval =="
ACCT=$(ip netns exec "$CLI" "$CLIENT" account --control-plane "$CPURL" | tr -dc '0-9')
echo "  account: ${ACCT:0:4}…"
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" connect \
    --control-plane "$CPURL" --account "$ACCT" --server srv-pq --key-file "$KEYFILE" \
    --rekey-secs 4 >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

echo "== wait for the handshake =="
sleep 5
RC=0
echo "== baseline: ping the server tunnel IP through the tunnel =="
if ip netns exec "$CLI" ping -c 2 -W 2 10.8.0.1 >/dev/null 2>&1; then
    echo "  tunnel up (initial PSK): PASS ✓"
else
    echo "  tunnel up (initial PSK): FAIL ✗"; RC=1
fi

echo "== let ~3 rotations happen (rekey every 4s), pinging throughout =="
# A continuous ping spanning several rotations. A rotation may drop a packet or two during the
# re-handshake window, so we require MOST to succeed, not all.
GOT=$(ip netns exec "$CLI" ping -c 15 -i 1 -W 2 10.8.0.1 2>/dev/null | grep -oE '[0-9]+ received' | grep -oE '^[0-9]+' || echo 0)
echo "  pings received across rotations: ${GOT}/15"
if [ "${GOT:-0}" -ge 11 ]; then
    echo "  traffic survives PSK rotation: PASS ✓"
else
    echo "  traffic survives PSK rotation: FAIL ✗  (too many drops)"; RC=1
fi

echo "== final: tunnel still up after the rotations =="
if ip netns exec "$CLI" ping -c 2 -W 2 10.8.0.1 >/dev/null 2>&1; then
    echo "  tunnel up (rotated PSK): PASS ✓"
else
    echo "  tunnel up (rotated PSK): FAIL ✗"; RC=1
fi

kill "$CLI_PID" 2>/dev/null || true; CLI_PID=""

echo "== both sides logged a rotation =="
if grep -q "rotated the post-quantum PSK" "$DIR/cli.log"; then
    echo "  client rotated PSK: PASS ✓"
else
    echo "  client rotated PSK: FAIL ✗"; RC=1
fi
if grep -q "rotating PSK for a peer" "$DIR/srv.log"; then
    echo "  server applied the rotated PSK: PASS ✓"
else
    echo "  server applied the rotated PSK: FAIL ✗"; RC=1
fi

if [ $RC -ne 0 ]; then
    echo "== control-plane log =="; cat "$DIR/cp.log"
    echo "== server log =="; cat "$DIR/srv.log"
    echo "== client log =="; cat "$DIR/cli.log"
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  the PQ PSK rotates on a live tunnel and traffic survives the swap."
else
    echo "RESULT: FAIL ✗  (see logs above)"
fi
exit $RC
