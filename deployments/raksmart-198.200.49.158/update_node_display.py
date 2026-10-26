"""Update console sources with a private rollback copy and state preservation."""
from datetime import datetime, timezone
import json
from pathlib import Path
from ssh_access import connect, execute, FOLDER

paths=['panel/node_info.py','panel/server.py','panel/web/index.html','panel/web/app.js','panel/web/style.css']
stage='/root/raksmart-proxy-deploy-20261009/node-display-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
PROGRAM=r'''
import hashlib, json, os, py_compile, shutil, socket, subprocess, time
from pathlib import Path

stage=Path(STAGE)
target=Path('/opt/vps-panel')
paths=PATHS
config=Path('/usr/local/etc/xray/config.json')
data=Path('/var/lib/vps-panel/state.private.json')
hashes={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in [config,data]}
before={}
def run(args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
    if result.returncode:
        (stage/'diagnostics.private.log').write_bytes(result.stdout+b'\n'+result.stderr)
        raise RuntimeError('Command failed: '+Path(args[0]).name)
    return result.stdout.decode().strip()
def start():
    run(['systemctl','start','vps-panel.service'])
    for _ in range(30):
        try:
            if run(['systemctl','is-active','vps-panel.service'])=='active':
                with socket.create_connection(('127.0.0.1',18787),timeout=.2):
                    return
        except (OSError, RuntimeError):
            pass
        time.sleep(.2)
    raise RuntimeError('Console did not become ready')

for filename in paths:
    source=stage/filename
    destination=target/filename
    if source.suffix=='.py':
        py_compile.compile(str(source),doraise=True)
    if destination.is_symlink():
        raise RuntimeError('Unexpected symlink destination')
    original=destination.read_bytes() if destination.exists() else None
    before[filename]=original
    backup=stage/'before'/filename
    backup.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if original is not None:
        backup.write_bytes(original)
        os.chmod(str(backup),0o600)
run(['systemctl','stop','vps-panel.service'])
installed={}
try:
    for filename in paths:
        destination=target/filename
        current=destination.read_bytes() if destination.exists() else None
        if current!=before[filename]:
            raise RuntimeError('Application source changed concurrently')
        content=(stage/filename).read_bytes()
        temporary=destination.with_name('.'+destination.name+'.node-display')
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(),0o644)
            stream.write(content)
        os.replace(str(temporary),str(destination))
        installed[filename]=content
    start()
except Exception:
    for filename,content in installed.items():
        destination=target/filename
        if destination.read_bytes()!=content:
            raise RuntimeError('External change prevents source rollback')
        original=before[filename]
        if original is None:
            destination.unlink()
        else:
            destination.write_bytes(original)
            os.chmod(str(destination),0o644)
    start()
    raise
after={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in [config,data]}
result={'success':True,'updated_files':paths,'console_active':True,
        'configuration_and_exit_state_preserved':hashes==after,'backup':str(stage/'before')}
print(json.dumps(result))
'''

client=connect()
try:
    code,output,error=execute(client,'install -d -m 0700 '+stage)
    if code: raise RuntimeError('Could not create private update directory')
    with client.open_sftp() as sftp:
        for filename in paths:
            remote=stage+'/'+filename
            # Parent directories contain application source only.
            parent=str(Path(remote).parent).replace('\\','/')
            code,_,_=execute(client,'install -d -m 0700 '+parent)
            if code: raise RuntimeError('Could not prepare candidate directory')
            sftp.put(str(FOLDER/'panel-release'/filename),remote)
            sftp.chmod(remote,0o600)
    program='STAGE='+repr(stage)+'\nPATHS='+repr(paths)+'\n'+PROGRAM
    code,output,error=execute(client,"python3 - <<'NODE_DISPLAY_UPDATE_PY'\n"+program+'\nNODE_DISPLAY_UPDATE_PY\n',timeout=55)
    (FOLDER/'node-display-update.private.log').write_text(output+'\n'+error,encoding='utf-8')
    if code: raise SystemExit('Node display update failed; inspect private log')
    result=json.loads(output)
    (FOLDER/'node-display-update.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result))
finally:
    client.close()
