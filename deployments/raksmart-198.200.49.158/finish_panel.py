"""Complete staged panel installation after Caddy directive correction."""
import json
from ssh_access import connect, execute, FOLDER
client=connect()
try:
    stage='/root/raksmart-proxy-deploy-20261009/panel'
    with client.open_sftp() as sftp:
        sftp.put(str(FOLDER/'Caddyfile'),stage+'/Caddyfile')
        sftp.chmod(stage+'/Caddyfile',0o600)
    command=r'''set -eu
install -m 0640 -o root -g caddy /root/raksmart-proxy-deploy-20261009/panel/Caddyfile /etc/caddy/Caddyfile
runuser -u caddy -- /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl daemon-reload
systemctl start vps-panel.service
systemctl start caddy.service
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if systemctl is-active --quiet vps-panel.service && systemctl is-active --quiet caddy.service; then
    systemctl enable vps-panel.service caddy.service
    printf 'PANEL_AND_CADDY_ACTIVE\n'
    exit 0
  fi
  sleep 0.5
done
exit 23
'''
    code,output,error=execute(client,command,timeout=45)
    (FOLDER/'panel-finish.private.log').write_text(output+'\n'+error,encoding='utf-8')
    result={'installed':code==0 and 'PANEL_AND_CADDY_ACTIVE' in output,
            'origin':'https://198-200-49-158.sslip.io:8443','remote_exit_code':code,
            'services':['vps-panel.service','caddy.service'],'external_https_verification_pending':True}
    (FOLDER/'panel-deployment-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
    if code: raise SystemExit('Panel completion failed; inspect private log')
finally:
    client.close()
