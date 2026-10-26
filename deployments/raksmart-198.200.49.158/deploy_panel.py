"""Package only application files; generate a new private console login."""
import hashlib
import json
from pathlib import Path
import secrets
import sys
import tarfile
from ssh_access import connect, execute, FOLDER

release=FOLDER/'panel-release'
sys.path.insert(0,str(release))
from panel.server import password_record
origin='https://198-200-49-158.sslip.io:8443'
login_path=FOLDER/'panel-login.private.json'
if login_path.exists():
    login=json.loads(login_path.read_text(encoding='utf-8'))
else:
    login={'url':origin+'/node-console/','username':'admin','password':secrets.token_urlsafe(24)}
    login_path.write_text(json.dumps(login,indent=2),encoding='utf-8')
(FOLDER/'panel-auth-seed.private.json').write_text(json.dumps(password_record(login['password'])),encoding='utf-8')
archive=FOLDER/'panel-release.private.tar.gz'
with tarfile.open(archive,'w:gz') as stream:
    for path in sorted(release.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts:
            stream.add(path,arcname=str(Path('release')/path.relative_to(release)))
expected=hashlib.sha256(archive.read_bytes()).hexdigest()
stage='/root/raksmart-proxy-deploy-20261009/panel'
client=connect()
try:
    code,output,error=execute(client,'install -d -m 0700 '+stage)
    if code: raise RuntimeError('Could not create staging directory')
    files=[('panel-release.private.tar.gz','release.tar.gz'),('install_panel.py','install_panel.py'),
           ('panel-auth-seed.private.json','auth-seed.private.json'),('panel-base.private.yaml','base.private.yaml'),
           ('Caddyfile','Caddyfile'),('caddy.service','caddy.service')]
    with client.open_sftp() as sftp:
        for local,remote in files:
            sftp.put(str(FOLDER/local),stage+'/'+remote)
            sftp.chmod(stage+'/'+remote,0o600)
    command="cd " + stage + "\nprintf '%s  release.tar.gz\\n' '" + expected + "' | sha256sum --check --status\ntar -xzf release.tar.gz\npython3 install_panel.py\n"
    code,output,error=execute(client,command,timeout=180)
    (FOLDER/'panel-deployment.private.log').write_text(output+'\n'+error,encoding='utf-8')
    if code: raise SystemExit('Panel installation failed; inspect private deployment log')
    print(output)
    (FOLDER/'panel-deployment-result.json').write_text(output,encoding='utf-8')
finally:
    client.close()
