"""Prepare and update console sources while preserving the live node and accounts."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import shutil
import tarfile

from ssh_access import connect, execute, FOLDER

ROOT = FOLDER.parents[1]
CHANGED = ['panel/server.py', 'panel/routing.py', 'panel/smart-routing.json',
           'panel/test_panel.py', 'panel/test_routing.py', 'panel/web/app.js',
           'panel/web/index.html', 'panel/web/style.css']


def prepare():
    destination = FOLDER / 'smart-routing-release'
    destination.mkdir(exist_ok=True)
    for candidate in (FOLDER / 'panel-release').rglob('*'):
        if (candidate.is_file() and '__pycache__' not in candidate.parts and candidate.suffix != '.pyc'
                and '.private.' not in candidate.name):
            relative = candidate.relative_to(FOLDER / 'panel-release')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(candidate.read_bytes())
    for name in CHANGED:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        text = (ROOT / name).read_text(encoding='utf-8')
        if name == 'panel/server.py':
            text = text.replace('from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer',
                                '''from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True''')
            text = text.replace('temporary.unlink(missing_ok=True)', 'base.unlink_if_exists(temporary)')
            text = text.replace('temporary_profile.unlink(missing_ok=True)', 'base.unlink_if_exists(temporary_profile)')
        if name == 'panel/test_panel.py':
            old = (FOLDER / 'panel-release' / name).read_text(encoding='utf-8')
            adoption = old.split('class ExistingRaksmartNodeTests', 1)[1].split('class PanelTests', 1)[0]
            text = 'import base64\n' + text.replace('class PanelTests',
                                                  'class ExistingRaksmartNodeTests' + adoption + 'class PanelTests', 1)
        if name.endswith('.py'):
            text = text.replace('capture_output=True, text=True,',
                                'stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,')
            ast.parse(text, filename=name, feature_version=(3, 6))
        target.write_text(text, encoding='utf-8')
    archive = FOLDER / 'smart-routing-release.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        for candidate in destination.rglob('*'):
            if candidate.is_file() and '__pycache__' not in candidate.parts and candidate.suffix != '.pyc':
                bundle.add(candidate, arcname='release/' + candidate.relative_to(destination).as_posix())
    manifest = {'files': CHANGED, 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
                'deployment_ip': '198.200.49.158',
                'frozen_at': datetime.now(timezone.utc).isoformat(),
                'source_sha256': {name: hashlib.sha256((destination / name).read_bytes()).hexdigest()
                                  for name in CHANGED}}
    (FOLDER / 'smart-routing-release-manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


PROGRAM = r'''
import hashlib, json, os, py_compile, shutil, socket, subprocess, sys, time, traceback
from pathlib import Path
from urllib.request import urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
data = Path('/var/lib/vps-panel/state.private.json')
protected = [Path('/usr/local/etc/xray/config.json'), Path('/usr/local/etc/raksmart-hy2/server.yaml'),
             Path('/etc/systemd/system/xray.service'), Path('/etc/systemd/system/raksmart-hy2.service'),
             Path('/etc/systemd/system/vps-panel.service'), Path('/etc/systemd/system/caddy.service'),
             Path('/etc/caddy/Caddyfile'), Path('/var/lib/vps-panel/auth.private.json'), Path('/etc/resolv.conf')]
base_profile = Path('/var/lib/vps-panel/base.private.yaml')
if base_profile.exists():
    protected.append(base_profile)
manifest = json.loads((stage / 'manifest.json').read_text())
files = manifest['files']
result = {'success': False, 'phase': 'preflight', 'updated_files': files, 'backup': str(stage / 'before')}
stopped = False
installed = []
before = {}
before_state = None

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def record(phase):
    result['phase'] = phase
    (stage / 'update-state.json').write_text(json.dumps(result, indent=2))

def run(args, timeout=30, cwd=None, env=None):
    response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=cwd, env=env)
    with (stage / 'commands.private.log').open('ab') as log:
        log.write(response.stdout + b'\n' + response.stderr)
    if response.returncode:
        raise RuntimeError('Command failed during ' + result['phase'] + ': ' + Path(args[0]).name)
    return response.stdout

def start():
    run(['systemctl', 'start', 'vps-panel.service'])
    for attempt in range(40):
        try:
            with urlopen('http://127.0.0.1:18787/api/session', timeout=1) as response:
                if response.status == 200 and not json.loads(response.read().decode())['authenticated']:
                    return
        except OSError:
            pass
        time.sleep(.2)
    raise RuntimeError('Updated panel did not become ready')

def state_identity(state):
    fields = ['base', 'public', 'short', 'auto_id', 'exits', 'applied_exits', 'active_id',
              'domains', 'applied_domains', 'profile', 'managed_hash', 'updated',
              'routing_mode', 'applied_routing_mode']
    return {key: state.get(key) for key in fields}

def wait_idle():
    from urllib.request import Request
    session = json.loads((stage / 'session.private.json').read_text())
    deadline = time.monotonic() + 60
    while True:
        query = Request('http://127.0.0.1:18787/api/state', headers={'Cookie': session['cookie']})
        with urlopen(query, timeout=3) as response:
            state = json.loads(response.read().decode())
        if (state.get('job') or {}).get('status') != 'running':
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('A live exit operation did not finish; update safely deferred')
        time.sleep(.5)

try:
    os.umask(0o077)
    record('preflight')
    for path in protected + [data]:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('Unexpected protected file')
    initial_hashes = {str(path): sha(path) for path in protected}
    for name in files:
        candidate = stage / 'release' / name
        if sha(candidate) != manifest['source_sha256'][name]:
            raise RuntimeError('Candidate source hash mismatch')
        if candidate.suffix == '.py':
            py_compile.compile(str(candidate), doraise=True)
        destination = target / name
        if destination.is_symlink():
            raise RuntimeError('Unexpected source symlink')
    record('linux-tests')
    environment = os.environ.copy()
    environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
    run([sys.executable, '-m', 'unittest', 'test_configure_reality', 'test_configure_static_exits',
         'panel.test_panel', 'panel.test_routing'], timeout=180, cwd=str(stage / 'release'), env=environment)
    if initial_hashes != {str(path): sha(path) for path in protected}:
        raise RuntimeError('Live configuration changed while the candidate was tested')
    record('backup-and-stop')
    backup = stage / 'before'
    backup.mkdir(mode=0o700)
    for name in files:
        destination = target / name
        original = destination.read_bytes() if destination.exists() else None
        before[name] = original
        if original is not None:
            path = backup / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original)
    wait_idle()
    run(['systemctl', 'stop', 'vps-panel.service'])
    stopped = True
    before_state = data.read_bytes()
    (backup / 'state.private.json').write_bytes(before_state)
    state_before = json.loads(before_state)
    initial_hashes = {str(path): sha(path) for path in protected}
    (backup / 'protected-hashes.json').write_text(json.dumps(initial_hashes, indent=2))
    if state_before['managed_hash'] != sha(protected[0]):
        raise RuntimeError('The live node state and configuration are inconsistent')
    record('install-sources')
    for name in files:
        destination = target / name
        if (destination.read_bytes() if destination.exists() else None) != before[name]:
            raise RuntimeError('Application source changed concurrently')
        candidate = stage / 'release' / name
        temporary = destination.with_name('.' + destination.name + '.smart-update')
        try:
            with temporary.open('xb') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(candidate.read_bytes())
            os.replace(str(temporary), str(destination))
        finally:
            if temporary.exists():
                temporary.unlink()
        installed.append(name)
    record('start-and-verify')
    start()
    current = json.loads(data.read_bytes())
    if state_identity(current) != state_identity(state_before):
        raise RuntimeError('Existing node or exit state changed during source update')
    for key in ['direct_domains', 'applied_direct_domains', 'rule_token']:
        if key in state_before and current.get(key) != state_before[key]:
            raise RuntimeError('Existing routing settings changed during migration')
    if len(current['history']) != len(state_before['history']):
        raise RuntimeError('Existing history changed during migration')
    for old, new in zip(state_before['history'], current['history']):
        if any(new.get(key) != value for key, value in old.items()):
            raise RuntimeError('Existing history content changed during migration')
    if initial_hashes != {str(path): sha(path) for path in protected}:
        raise RuntimeError('A protected node, account or service configuration changed')
    for service in ['vps-panel.service', 'caddy.service', 'xray.service', 'raksmart-hy2.service']:
        run(['systemctl', 'is-active', '--quiet', service])
        run(['systemctl', 'is-enabled', '--quiet', service])
    result.update(success=True, configuration_and_accounts_preserved=True, auto_identity_preserved=True,
                  exit_state_preserved=True, rule_subscription_token_initialized=bool(current.get('rule_token')))
    record('complete')
except BaseException:
    (stage / 'error.private.log').write_text(traceback.format_exc())
    if stopped:
        try:
            run(['systemctl', 'stop', 'vps-panel.service'])
            for name in reversed(installed):
                destination = target / name
                if before[name] is None:
                    destination.unlink()
                else:
                    destination.write_bytes(before[name])
                    os.chmod(str(destination), 0o644)
            if before_state is not None:
                data.write_bytes(before_state)
                os.chmod(str(data), 0o600)
            start()
            result['rolled_back'] = True
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result.update(rolled_back=False, rollback_failed=True)
    record('failed')
    print(json.dumps(result))
    sys.exit(1)
print(json.dumps(result))
'''


def deploy(manifest):
    import smart_access as live
    if (manifest.get('deployment_ip') != '198.200.49.158' or
            manifest['files'] != CHANGED or
            hashlib.sha256((FOLDER / 'smart-routing-release.tar.gz').read_bytes()).hexdigest()
            != manifest['archive_sha256']):
        raise RuntimeError('The frozen release manifest or archive is inconsistent')
    for name in CHANGED:
        if hashlib.sha256((FOLDER / 'smart-routing-release' / name).read_bytes()).hexdigest() != manifest['source_sha256'][name]:
            raise RuntimeError('The frozen release source is inconsistent')
    login = json.loads((FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
    status, headers, _ = live.request('POST', 'api/login',
                                     {'username': login['username'], 'password': login['password']})
    if status != 200:
        raise RuntimeError('Could not authenticate the read-only update preflight')
    session_path = FOLDER / 'smart-update-session.private.json'
    session_path.write_text(json.dumps({'cookie': headers['Set-Cookie'].split(';', 1)[0]}), encoding='utf-8')
    stage = '/root/raksmart-proxy-deploy-20261009/smart-routing-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3)
    client = connect()
    try:
        code, _, _ = execute(client, 'install -d -m 0700 ' + shlex.quote(stage))
        if code:
            raise RuntimeError('Could not create update stage')
        with client.open_sftp() as sftp:
            sftp.put(str(FOLDER / 'smart-routing-release.tar.gz'), stage + '/release.tar.gz')
            sftp.put(str(FOLDER / 'smart-routing-release-manifest.json'), stage + '/manifest.json')
            sftp.put(str(session_path), stage + '/session.private.json')
            session_path.unlink()
            for name in ['release.tar.gz', 'manifest.json', 'session.private.json']:
                sftp.chmod(stage + '/' + name, 0o600)
        program = 'STAGE = ' + repr(stage) + '\n' + PROGRAM
        command = ('set -eu\ncd ' + shlex.quote(stage) + '\n' +
                   'printf ' + shlex.quote('%s  release.tar.gz\n') + ' ' + shlex.quote(manifest['archive_sha256']) +
                   ' | sha256sum --check --status\ntar -xzf release.tar.gz\n' +
                   "python3 - <<'SMART_ROUTING_UPDATE'\n" + program + '\nSMART_ROUTING_UPDATE\n')
        code, output, error = execute(client, command, timeout=240)
        (FOLDER / 'smart-routing-update.private.log').write_text(output + '\n' + error, encoding='utf-8')
        with client.open_sftp() as sftp:
            sftp.get(stage + '/update-state.json', str(FOLDER / 'smart-routing-update.json'))
        if code:
            raise RuntimeError('Smart routing update failed; inspect the private update log and report')
        result = json.loads(output)
        if not result['success']:
            raise RuntimeError('Update did not complete')
        for name in CHANGED:
            shutil.copyfile(str(FOLDER / 'smart-routing-release' / name), str(FOLDER / 'panel-release' / name))
        print(json.dumps(result))
    finally:
        client.close()
        if session_path.exists():
            session_path.unlink()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if args.prepare_only:
        manifest = prepare()
        print(json.dumps({'prepared': True, 'files': CHANGED, 'python_syntax': '3.6'}))
    else:
        manifest_path = FOLDER / 'smart-routing-release-manifest.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8')) if manifest_path.exists() else prepare()
        deploy(manifest)
