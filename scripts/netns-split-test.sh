#!/usr/bin/env bash
# 3D split-tunnelling live verification (FIB-level): prove that under a full-tunnel client,
# a `split_exclude` CIDR routes AROUND the tunnel (via the original default gateway) while
# everything else is swung into the tunnel. Companion to netns-classic-test.sh, which proves
# the split-INCLUDE auto-route end-to-end (an allowed_ips CIDR reaching the exit via oxide0).
#
# Topology — the classic underlay: oxide-cli --10.50.0.0/24-- oxide-srv --10.60.0.0/24-- net.
# The client runs FULL-TUNNEL (0.0.0.0/0) with split_exclude = ["10.60.0.0/24"] and a default
# route via the server underlay (10.50.0.1). We then read the kernel FIB with `ip route get`:
#
#   * a public IP (8.8.8.8)  -> dev oxide0        (default swung into the tunnel)
#   * 10.60.0.5 (excluded)   -> via 10.50.0.1     (pinned around the tunnel, NOT oxide0)
#   * 10.50.0.1 (endpoint)   -> dev veth-cs       (endpoint host-route pin)
#
# Routes are installed by run_tunnel before the engine connects, so this asserts the routing
# plan directly and doesn't depend on a completed handshake.
#
# Requires root (CAP_NET_ADMIN).  Run:  sudo bash scripts/netns-split-test.sh
set -euo pipefail

CLI=oxide-cli
SRV=oxide-srv
NET=oxide-net
DIR=$(mktemp -d)
BIN=target/debug

cleanup() {
    set +e
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "${CLI_PID:-}" ] && kill "$CLI_PID" 2>/dev/null
    ip netns del "$CLI" 2>/dev/null
    ip netns del "$SRV" 2>/dev/null
    ip netns del "$NET" 2>/dev/null
    rm -rf "$DIR"
}
trap cleanup EXIT

if [ -z "${OXIDE_SKIP_BUILD:-}" ]; then
    echo "== building =="
    ( . "$HOME/.cargo/env" 2>/dev/null; cargo build -p oxide-serverd -p oxide-client )
fi
SERVERD="$PWD/$BIN/oxide-serverd"
CLIENT="$PWD/$BIN/oxide-client"

echo "== keys =="
SPRIV=$("$SERVERD" genkey); SPUB=$(echo "$SPRIV" | "$SERVERD" pubkey)
CPRIV=$("$CLIENT"  genkey); CPUB=$(echo "$CPRIV" | "$CLIENT"  pubkey)

cat > "$DIR/server.toml" <<EOF
[interface]
private_key = "$SPRIV"
address = "10.8.0.1/24"
listen_port = 51820
[nat]
egress = "veth-sn"
[[peer]]
public_key = "$CPUB"
allowed_ips = ["10.8.0.2/32"]
EOF

# Client: FULL TUNNEL, but exclude the 10.60.0.0/24 subnet from the tunnel.
cat > "$DIR/client.toml" <<EOF
[interface]
private_key = "$CPRIV"
address = "10.8.0.2/24"
split_exclude = ["10.60.0.0/24"]
[[peer]]
public_key = "$SPUB"
endpoint = "10.50.0.1:51820"
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 25
EOF

echo "== namespaces + veths =="
for ns in "$CLI" "$SRV" "$NET"; do ip netns del "$ns" 2>/dev/null || true; done
ip netns add "$CLI"; ip netns add "$SRV"; ip netns add "$NET"
ip link add veth-cs netns "$CLI" type veth peer name veth-sc netns "$SRV"
ip -n "$CLI" addr add 10.50.0.2/24 dev veth-cs
ip -n "$SRV" addr add 10.50.0.1/24 dev veth-sc
ip link add veth-sn netns "$SRV" type veth peer name veth-ns netns "$NET"
ip -n "$SRV" addr add 10.60.0.1/24 dev veth-sn
ip -n "$NET" addr add 10.60.0.2/24 dev veth-ns
for ns in "$CLI" "$SRV" "$NET"; do ip -n "$ns" link set lo up; done
ip -n "$CLI" link set veth-cs up
ip -n "$SRV" link set veth-sc up
ip -n "$SRV" link set veth-sn up
ip -n "$NET" link set veth-ns up
# The client needs an original default route for run_tunnel to find a gateway to pin
# the endpoint and the excluded CIDR against.
ip -n "$CLI" route add default via 10.50.0.1 dev veth-cs

echo "== start daemons =="
ip netns exec "$SRV" env RUST_LOG=info "$SERVERD" up --config "$DIR/server.toml" >"$DIR/srv.log" 2>&1 &
SRV_PID=$!
ip netns exec "$CLI" env RUST_LOG=info "$CLIENT" up --config "$DIR/client.toml" >"$DIR/cli.log" 2>&1 &
CLI_PID=$!

echo "== wait for the client to install routing =="
sleep 4

RC=0
check() { # desc, target, must-match
    local desc=$1 target=$2 want=$3
    local got
    got=$(ip netns exec "$CLI" ip route get "$target" 2>/dev/null | head -1)
    if echo "$got" | grep -q "$want"; then
        echo "  $desc: PASS ✓  ($got)"
    else
        echo "  $desc: FAIL ✗  (got: ${got:-<none>}, wanted: $want)"
        RC=1
    fi
}

echo "== FIB assertions =="
check "public IP swung into tunnel" 8.8.8.8      "dev oxide0"
check "excluded CIDR bypasses tunnel" 10.60.0.5  "via 10.50.0.1"
check "excluded CIDR NOT via oxide0" 10.60.0.5   "dev veth-cs"
check "server endpoint pinned to underlay" 10.50.0.1 "dev veth-cs"

if [ $RC -ne 0 ]; then
    echo "== client log =="; cat "$DIR/cli.log"
    echo "== client routes =="; ip netns exec "$CLI" ip route
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  split_exclude routes around the tunnel; the default is tunneled."
else
    echo "RESULT: FAIL ✗  (see logs above)"
fi
exit $RC
