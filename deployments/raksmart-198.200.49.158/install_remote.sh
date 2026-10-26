#!/bin/bash
set -euo pipefail
stage=/root/raksmart-proxy-deploy-20261009
binary=/usr/local/bin/xray
config=/usr/local/etc/xray/config.json
unit=/etc/systemd/system/xray.service

for path in "$binary" "$config" "$unit"; do
    if test -e "$path"; then
        printf 'STOPPED: deployment target already exists: %s\n' "$path" >&2
        exit 20
    fi
done
if ss -lntH | awk '{print $4}' | grep -Eq '(^|:)443$'; then
    printf 'STOPPED: TCP 443 is already listening\n' >&2
    exit 21
fi
printf '%s  %s\n' '8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed' "$stage/xray-ready" | sha256sum -c -
"$stage/xray-ready" run -test -config "$stage/config.json"

created_binary=0
created_config=0
created_unit=0
rollback() {
    result=$?
    if test "$result" -ne 0; then
        printf 'Installation failed; reverting this deployment.\n' >&2
        if test "$created_unit" = 1; then
            systemctl stop xray.service || true
            systemctl disable xray.service || true
            rm -f -- "$unit"
            systemctl daemon-reload || true
        fi
        if test "$created_config" = 1; then rm -f -- "$config"; fi
        if test "$created_binary" = 1; then rm -f -- "$binary"; fi
    fi
}
trap rollback EXIT

if ! id xray >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /sbin/nologin xray
fi
install -d -m 750 -o root -g xray /usr/local/etc/xray
install -m 755 -o root -g root "$stage/xray-ready" "$binary"
created_binary=1
setcap cap_net_bind_service=+ep "$binary"
install -m 640 -o root -g xray "$stage/config.json" "$config"
created_config=1
runuser -u xray -- "$binary" run -test -config "$config"
install -m 644 -o root -g root "$stage/xray.service" "$unit"
created_unit=1
systemctl daemon-reload
systemctl enable xray.service
systemctl start xray.service
for attempt in 1 2 3 4 5; do
    if systemctl is-active --quiet xray.service && ss -lntH | awk '{print $4}' | grep -Eq '(^|:)443$'; then
        break
    fi
    sleep 1
done
systemctl is-active --quiet xray.service
ss -lntH | awk '{print $4}' | grep -Eq '(^|:)443$'
printf '\nService status\n'
systemctl is-active xray.service
systemctl is-enabled xray.service
systemctl show xray.service -p User -p Group -p MainPID -p ExecMainStatus
printf '\nTCP listener\n'
ss -lntp | grep ':443 '
printf '\nConfig ownership and binary capability\n'
stat -c '%a %U:%G %n' "$config"
getcap "$binary"
printf '\nSUCCESS: Xray is running on TCP 443.\n'
