"""Raise only the authenticated backup preview body's Caddy ingress limit."""

from datetime import datetime, timezone
import hashlib
import json
import secrets
import shlex

import frontend_motion_access as live
from ssh_access import FOLDER, connect, execute


PROGRAM = r'''
import hashlib, json, os, subprocess, time
from pathlib import Path
stage=Path(STAGE)
target=Path('/etc/caddy/Caddyfile')
result={'success':False,'scope':'backup_preview_ingress_only','services_restarted':False,
        'public_body_limit_bytes':48000000,'stage':str(stage)}
def require(value,message):
 if not value: raise RuntimeError(message)
def run(args):
 outcome=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 (stage/'commands.private.log').open('ab').write(outcome.stdout+b'\n'+outcome.stderr)
 require(outcome.returncode==0,'Caddy validation or reload failed')
 return outcome.stdout
def status(service):
 text=run(['systemctl','show',service,'--property=MainPID','--property=ActiveState','--property=ExecMainStartTimestampMonotonic']).decode()
 return dict(line.split('=',1) for line in text.splitlines() if '=' in line)
def sha(data): return hashlib.sha256(data).hexdigest()
def install(data):
 temp=target.with_name('.Caddyfile.backup-upload-'+stage.name[-6:])
 info=target.stat()
 with temp.open('xb') as stream:
  os.fchmod(stream.fileno(),info.st_mode&0o777)
  os.fchown(stream.fileno(),info.st_uid,info.st_gid)
  stream.write(data);stream.flush();os.fsync(stream.fileno())
 os.replace(str(temp),str(target))
os.umask(0o077)
require(target.is_file() and not target.is_symlink(),'Unexpected Caddy configuration')
original=target.read_bytes()
(stage/'Caddyfile.before').write_bytes(original)
text=original.decode('utf-8')
require('/node-console/api/backups/preview' not in text,'Preview route already has a separate limit')
marker='\thandle_path /node-console/* {'
require(text.count(marker)==1,'The existing management route is not unique')
newline='\r\n' if '\r\n' in text else '\n'
addition='\n'.join([
'\thandle /node-console/api/backups/preview {',
'\t\turi strip_prefix /node-console',
'\t\trequest_body {',
'\t\t\tmax_size 48MB',
'\t\t}',
'\t\treverse_proxy 127.0.0.1:18787 {',
'\t\t\theader_up X-Real-IP {remote_host}',
'\t\t}',
'\t}',
'']).replace('\n',newline)+newline
candidate=text.replace(marker,addition+marker,1).encode('utf-8')
require(candidate.replace(addition.encode('utf-8'),b'',1)==original,'Unrelated Caddy content changed')
candidate_path=stage/'Caddyfile.candidate'
candidate_path.write_bytes(candidate)
run(['/usr/local/bin/caddy','validate','--config',str(candidate_path),'--adapter','caddyfile'])
before={name:status(name) for name in ['caddy.service','raksmart-hy2.service','vps-panel.service','xray.service']}
registry=json.loads(Path('/var/lib/vps-panel/users.private.json').read_text())
for user in registry['users']:
 name='xray-panel@'+user['id']+'.service';before[name]=status(name)
changed=False
try:
 require(target.read_bytes()==original,'Caddy changed before installation')
 install(candidate);changed=True
 run(['systemctl','reload','caddy.service'])
 for name,old in before.items():
  require(status(name)==old,'A service process changed during the route reload')
 require(target.read_bytes()==candidate,'Installed Caddy content changed')
 result.update(success=True,existing_requests_limit_bytes=64000,
               caddy_before_sha256=sha(original),caddy_after_sha256=sha(candidate),
               caddy_process_preserved=True,proxy_panel_hy2_processes_preserved=True)
except BaseException:
 if changed:
  require(target.read_bytes()==candidate,'A concurrent Caddy change prevents rollback')
  install(original);run(['systemctl','reload','caddy.service'])
 raise
finally:
 (stage/'report.json').write_text(json.dumps(result))
print(json.dumps(result))
'''


def main():
    stage = "/root/raksmart-proxy-deploy-20261009/backup-upload-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    client = connect()
    try:
        code, unused, error = execute(client, "install -d -m 0700 " + shlex.quote(stage))
        live.require(code == 0, "Could not create an isolated Caddy route stage")
        code, output, error = execute(client, "python3 - <<'BACKUP_UPLOAD_ROUTE'\nSTAGE=" + repr(stage) + "\n" + PROGRAM + "\nBACKUP_UPLOAD_ROUTE\n", timeout=100)
        with client.open_sftp() as sftp:
            for remote, local in [("report.json", "operations-backup-upload-update.json"),
                                  ("Caddyfile.before", "operations-Caddyfile-before.private"),
                                  ("Caddyfile.candidate", "Caddyfile")]:
                sftp.get(stage + "/" + remote, str(FOLDER / local))
        live.require(code == 0, "Backup ingress update failed; inspect its private stage")
        report = json.loads((FOLDER / "operations-backup-upload-update.json").read_text())
        live.require(report["success"], "Backup ingress acceptance failed")
        print(json.dumps(report))
    finally:
        client.close()


if __name__ == "__main__":
    main()
