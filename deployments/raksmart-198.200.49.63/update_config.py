"""Apply a validated target change to this deployment with rollback."""
import json
from ssh_access import connect, execute, FOLDER

stage = '/root/raksmart-proxy-deploy-20261009'
client = connect()
try:
    with client.open_sftp() as sftp:
        sftp.put(str(FOLDER/'server.private.json'), stage+'/config.new.json', confirm=True)
        sftp.chmod(stage+'/config.new.json', 0o600)
    command = '''
set -euo pipefail
stage=/root/raksmart-proxy-deploy-20261009
config=/usr/local/etc/xray/config.json
/usr/local/bin/xray run -test -config "$stage/config.new.json"
backup="$stage/config.before-update-$(date -u +%Y%m%dT%H%M%S).private.json"
cp -p -- "$config" "$backup"
rollback() {
    result=$?
    if test "$result" -ne 0; then
        cp -p -- "$backup" "$config"
        systemctl restart xray.service || true
    fi
}
trap rollback EXIT
install -m 640 -o root -g xray "$stage/config.new.json" "$config"
runuser -u xray -- /usr/local/bin/xray run -test -config "$config"
systemctl restart xray.service
for attempt in 1 2 3 4 5; do
    if systemctl is-active --quiet xray.service && ss -lntH | awk '{print $4}' | grep -Eq '(^|:)443$'; then
        break
    fi
    sleep 1
done
systemctl is-active --quiet xray.service
systemctl is-enabled xray.service
ss -lntp | grep ':443 '
stat -c '%a %U:%G %n' "$config"
printf 'SUCCESS: Updated validated Xray configuration and restarted service.\n'
'''
    code, output, error = execute(client, command, timeout=30)
    (FOLDER/'configuration-update-result.json').write_text(json.dumps({
        'exit_code':code,'stdout':output,'stderr':error,
    },indent=2),encoding='utf-8')
    print(output)
    if error:
        print(error)
    if code:
        raise SystemExit(code)
finally:
    client.close()
