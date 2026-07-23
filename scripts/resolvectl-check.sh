#!/usr/bin/env bash
# Verify the systemd-resolved DNS backend (net-linux::dns): per-link DNS via
# `resolvectl dns <if> <ip>` + a `~.` routing domain, then `resolvectl revert`.
#
# Uses a throwaway *dummy* interface, so it doesn't touch a real tunnel or the host's DNS —
# it just exercises the exact resolvectl commands the client would run. Requires
# systemd-resolved to be running (its stub resolv.conf must exist) and root.
#
# On a box without resolved (this one), start it just for the check and stop it after — no
# permanent change, and /etc/resolv.conf is not touched:
#   sudo systemctl start systemd-resolved
#   sudo bash scripts/resolvectl-check.sh
#   sudo systemctl stop systemd-resolved
set -euo pipefail

IF=oxidedns0
DNS=10.123.45.6

cleanup() {
    set +e
    resolvectl revert "$IF" 2>/dev/null
    ip link del "$IF" 2>/dev/null
}
trap cleanup EXIT

if [ ! -e /run/systemd/resolve/stub-resolv.conf ]; then
    echo "systemd-resolved isn't running (no /run/systemd/resolve/stub-resolv.conf)."
    echo "Start it for the check:  sudo systemctl start systemd-resolved"
    echo "(then re-run; stop it after with:  sudo systemctl stop systemd-resolved)"
    exit 1
fi

echo "== dummy interface $IF =="
ip link del "$IF" 2>/dev/null || true
ip link add "$IF" type dummy
ip link set "$IF" up

echo "== apply the tunnel DNS exactly as net-linux::dns does =="
# These are `resolvectl_dns_args` / `resolvectl_domain_args` from net-linux::dns.
resolvectl dns "$IF" "$DNS"
resolvectl domain "$IF" '~.'

echo "== resolvectl status $IF =="
resolvectl status "$IF" | grep -E "DNS Servers|Current DNS|DNS Domain" | sed 's/^/  /' || true

RC=0
STATUS=$(resolvectl status "$IF")
if echo "$STATUS" | grep -q "$DNS"; then
    echo "  DNS server set on the link: PASS ✓"
else
    echo "  DNS server set on the link: FAIL ✗"
    RC=1
fi
if echo "$STATUS" | grep -q "~\."; then
    echo "  ~. routing domain set: PASS ✓  (resolved routes ALL queries to the tunnel DNS)"
else
    echo "  ~. routing domain set: FAIL ✗"
    RC=1
fi

echo "== revert =="
resolvectl revert "$IF"
if resolvectl status "$IF" | grep -q "$DNS"; then
    echo "  revert cleared it: FAIL ✗ (DNS still present)"
    RC=1
else
    echo "  revert cleared it: PASS ✓"
fi

echo
if [ $RC -eq 0 ]; then
    echo "RESULT: PASS ✓  systemd-resolved DNS backend works (per-link DNS + ~. routing domain + revert)."
else
    echo "RESULT: FAIL ✗"
fi
exit $RC
