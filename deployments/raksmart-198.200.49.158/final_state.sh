set -eu
python3 - <<'PY'
from pathlib import Path
import hashlib, json, subprocess
def command(args):
    return subprocess.check_output(args).decode().strip()
services={}
for name in ['xray.service','raksmart-hy2.service','vps-panel.service','caddy.service']:
    services[name]={'active':command(['systemctl','is-active',name]),'enabled':command(['systemctl','is-enabled',name])}
config=Path('/usr/local/etc/xray/config.json')
panel=json.loads(Path('/var/lib/vps-panel/state.private.json').read_text())
live_hash=hashlib.sha256(config.read_bytes()).hexdigest()
if live_hash != panel['managed_hash']:
    raise RuntimeError('Panel and live Xray config differ')
pid=int(command(['systemctl','show','vps-panel.service','-p','MainPID']).split('=',1)[1])
status=Path('/proc/'+str(pid)+'/status').read_text()
capability=int(next(line.split()[1] for line in status.splitlines() if line.startswith('CapBnd:')),16)
if not capability & (1<<10):
    raise RuntimeError('Panel cannot launch the capability-enabled Xray validator')
marker=Path('/opt/vps-panel/install-marker.json')
if not marker.exists():
    marker.write_text('{"application":"Private Node Console","platform":"CentOS7"}\n')
result={'services':services,'xray_config_sha256':live_hash,'panel_managed_config_matches':True,
        'panel_static_exit_count':len(panel['exits']),'panel_validator_capability':True,
        'manager_origin':'https://198-200-49-158.sslip.io:8443','proxy_ports':{'REALITY':'TCP443','HY2':'UDP443'}}
print(json.dumps(result))
PY
