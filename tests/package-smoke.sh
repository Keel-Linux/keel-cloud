#!/bin/bash
# package-smoke.sh DIR: install python3-keel-cloud and keel-cloud-api from
# DIR on this trixie system and check the service the package starts:
# its own user, [::]:8443, TLS only, a key made by the command line works
# and only its hash is stored. Run as root in a throwaway container (CI).
set -euo pipefail

dir=$1
fail() { echo "package-smoke: $*" >&2; exit 1; }

apt-get install -y -qq --no-install-recommends procps iproute2 curl \
    "$dir"/python3-keel-cloud_*_all.deb "$dir"/keel-cloud-api_*_all.deb

for i in $(seq 1 30); do
    systemctl is-active --quiet keel-cloud-api && break
    sleep 1
done
systemctl is-active --quiet keel-cloud-api \
    || { journalctl -u keel-cloud-api --no-pager | tail -20; fail "not active"; }

user=$(ps -o user= -p "$(systemctl show -p MainPID --value keel-cloud-api)")
[ "$user" = keel-cloud ] || fail "runs as $user, not keel-cloud"
ss -ltnH | grep -q '\[::\]:8443' || fail "not listening on [::]:8443"

[ "$(stat -c '%U:%G %a' /etc/keel-cloud/tls/key.pem)" = "root:keel-cloud 640" ] \
    || fail "the TLS key is not root:keel-cloud 0640"

code=$(curl -s -o /dev/null -w '%{http_code}' "http://[::1]:8443/v1/health" \
    || true)
[ "$code" = 000 ] || fail "plain HTTP answered $code"

name=$(hostname -f 2>/dev/null || hostname)
curl -sf --cacert /etc/keel-cloud/tls/cert.pem \
    --resolve "$name:8443:[::1]" "https://$name:8443/v1/health" \
    | grep -q '"ok"' || fail "no health over TLS"

account=$(keel-cloud account create smoke)
enroll=$(keel-cloud key create smoke)
[[ $enroll == kc1e_* ]] || fail "no enrollment key"
status=$(curl -s -o /dev/null -w '%{http_code}' --cacert /etc/keel-cloud/tls/cert.pem \
    --resolve "$name:8443:[::1]" -H "Authorization: Bearer $account" \
    "https://$name:8443/v1/sets")
[ "$status" = 200 ] || fail "the account key was refused: $status"
if grep -rqF -e "${enroll#kc1e_}" /var/lib/keel-cloud; then
    fail "a plain key is in the database"
fi
[ "$(stat -c %U /var/lib/keel-cloud/cloud.db)" = keel-cloud ] \
    || fail "the database is not the service's"

echo "package-smoke: keel-cloud-api runs as keel-cloud on [::]:8443, TLS only"
