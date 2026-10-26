"""Freeze and safely publish the isolated multi-user console to server 63.

Default deployment uses reviewed frozen files. --prepare-only is local only.
The existing administrator Xray, HY2, Caddy, auth and state are protected.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import tarfile

from ssh_access import FOLDER, connect, execute
import frontend_motion_access as live

ROOT = FOLDER.parents[1]
FILES = ['configure_static_exits.py', 'test_configure_static_exits.py',
         'panel/server.py', 'panel/accounts.py', 'panel/test_accounts.py', 'panel/test_panel.py',
         'panel/test_multiuser_http.py',
         'panel/web/app.js', 'panel/web/index.html', 'panel/web/style.css']
RELEASE = FOLDER / 'multiuser-release'
ARCHIVE = FOLDER / 'multiuser-release.tar.gz'
MANIFEST = FOLDER / 'multiuser-release-manifest.json'
REPORT = FOLDER / 'multiuser-update.json'
ORIGIN = live.ORIGIN


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compatible(text, name):
    if Path(name).name.startswith('test_'):
        # Python 3.6 mock._Call has positional tuple access only.
        # These tests exclusively inspect call_args and call_args_list pairs.
        text = re.sub(r'\b(run\.call_args|call)\.args\b', r'\1[0]', text)
        text = re.sub(r'\b(run\.call_args|call)\.kwargs\b', r'\1[1]', text)
    if name == 'panel/server.py':
        text = text.replace('from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer',
                            '''from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from http.server import ThreadingHTTPServer
except ImportError:
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True''')
    text = text.replace('capture_output=True', 'stdout=subprocess.PIPE, stderr=subprocess.PIPE')
    text = text.replace('text=True', 'universal_newlines=True')
    if '.unlink(missing_ok=True)' in text:
        text = re.sub(r'([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.unlink\(missing_ok=True\)',
                      r'_unlink_if_exists(\1)', text)
        text += '''\n\ndef _unlink_if_exists(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass
'''
        # This helper must be available when main() executes.
        main = '\nif __name__ == "__main__":\n'
        if main in text:
            first, rest = text.split(main, 1)
            guard, helper = rest.split('\n\ndef _unlink_if_exists', 1)
            text = first + '\n\ndef _unlink_if_exists' + helper + main + guard
    return text


def prepare():
    for candidate in (FOLDER / 'panel-release').rglob('*'):
        if candidate.is_file() and '__pycache__' not in candidate.parts and candidate.suffix != '.pyc' and '.private.' not in candidate.name:
            target = RELEASE / candidate.relative_to(FOLDER / 'panel-release')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(candidate.read_bytes())
    for name in FILES:
        target = RELEASE / name
        target.parent.mkdir(parents=True, exist_ok=True)
        # configure_reality.py stays byte-for-byte server 63's adopted adapter;
        # configure_static_exits rewrites the generated client port as needed.
        text = (ROOT / name).read_text(encoding='utf-8')
        if name == 'panel/test_panel.py':
            original = (FOLDER / 'panel-release' / name).read_text(encoding='utf-8')
            adoption = original.split('class ExistingRaksmartNodeTests', 1)[1].split('class PanelTests', 1)[0]
            text = 'import base64\n' + text.replace('class PanelTests',
                                                   'class ExistingRaksmartNodeTests' + adoption + 'class PanelTests', 1)
        if name.endswith('.py'):
            text = compatible(text, name)
            ast.parse(text, filename=name, feature_version=(3, 6))
        target.write_text(text, encoding='utf-8')
    subprocess.run(['node', '--check', str(RELEASE / 'panel/web/app.js')], check=True,
                   capture_output=True, timeout=15, creationflags=live.NO_WINDOW)
    ast.parse(PROGRAM, filename='multiuser_remote_update.py', feature_version=(3, 6))
    with tarfile.open(ARCHIVE, 'w:gz') as bundle:
        for candidate in RELEASE.rglob('*'):
            if candidate.is_file() and '__pycache__' not in candidate.parts and candidate.suffix != '.pyc' and '.private.' not in candidate.name:
                bundle.add(candidate, arcname='release/' + candidate.relative_to(RELEASE).as_posix())
        bundle.add(FOLDER / 'multiuser-xray-panel@.service', arcname='xray-panel@.service')
        bundle.add(FOLDER / 'multiuser-panel-paths.conf', arcname='multiuser-panel-paths.conf')
    manifest = {'deployment_ip': live.IP, 'files': FILES,
                'prepared_at': datetime.now(timezone.utc).isoformat(),
                'archive_sha256': sha(ARCHIVE),
                'source_sha256': {name: sha(RELEASE / name) for name in FILES},
                'template_sha256': sha(FOLDER / 'multiuser-xray-panel@.service'),
                'dropin_sha256': sha(FOLDER / 'multiuser-panel-paths.conf')}
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return manifest


def frozen_manifest():
    live.require(MANIFEST.is_file(), 'Prepare and review the frozen release before deployment')
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    live.require(manifest.get('deployment_ip') == live.IP and manifest.get('files') == FILES,
                 'Unexpected release target or files')
    live.require(sha(ARCHIVE) == manifest['archive_sha256'], 'Frozen archive changed')
    for name in FILES:
        live.require(sha(RELEASE / name) == manifest['source_sha256'][name], 'Frozen source changed')
    return manifest


PROGRAM = r'''
import hashlib, json, os, py_compile, re, shutil, socket, subprocess, sys, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
data = Path('/var/lib/vps-panel/state.private.json')
registry = Path('/var/lib/vps-panel/users.private.json')
template = Path('/etc/systemd/system/xray-panel@.service')
dropin = Path('/etc/systemd/system/vps-panel.service.d/multiuser-paths.conf')
member_root = Path('/usr/local/etc/xray-members')
protected = [Path('/usr/local/etc/xray/config.json'), Path('/usr/local/etc/raksmart-hy2/server.yaml'),
             Path('/etc/systemd/system/xray.service'), Path('/etc/systemd/system/raksmart-hy2.service'),
             Path('/etc/systemd/system/vps-panel.service'), Path('/etc/systemd/system/caddy.service'),
             Path('/etc/caddy/Caddyfile'), Path('/var/lib/vps-panel/auth.private.json'),
             Path('/etc/resolv.conf'), Path('/var/lib/vps-panel/base.private.yaml')]
old_services = ['xray.service', 'raksmart-hy2.service', 'caddy.service']
manifest = json.loads((stage / 'manifest.json').read_text())
files = manifest['files']
result = {'success': False, 'phase': 'preflight', 'deployment_ip': '198.200.49.63',
          'updated_files': files, 'backup': str(stage / 'before'), 'admin_xray_restarted': False,
          'local_firewall_changed': False, 'created_users': []}
stopped = False
installed = []
before = {}
state_before = None
registry_before = None
created_ids = []
created_member_root = False
created_template = False
created_dropin = False

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def record(phase):
    result['phase'] = phase
    (stage / 'update-state.json').write_text(json.dumps(result, indent=2))

def run(args, timeout=30, cwd=None, env=None, check=True):
    response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=cwd, env=env)
    with (stage / 'commands.private.log').open('ab') as log:
        log.write(response.stdout + b'\n' + response.stderr)
    if check and response.returncode:
        raise RuntimeError('Command failed during ' + result['phase'] + ': ' + Path(args[0]).name)
    return response

def service_snapshot():
    properties = ['ActiveState', 'SubState', 'UnitFileState', 'MainPID',
                  'ActiveEnterTimestampMonotonic', 'ExecMainStartTimestampMonotonic']
    output = {}
    for service in old_services:
        answer = run(['systemctl', 'show', service])
        fields = dict(line.split('=', 1) for line in answer.stdout.decode().splitlines() if '=' in line)
        output[service] = {key: fields[key] for key in properties}
        require(fields['ActiveState'] == 'active' and fields['UnitFileState'] == 'enabled',
                'A protected service is not active and enabled')
    return output

def start():
    run(['systemctl', 'start', 'vps-panel.service'])
    for attempt in range(40):
        try:
            with urlopen('http://127.0.0.1:18787/api/session', timeout=1) as response:
                if response.status == 200 and not json.loads(response.read().decode())['authenticated']:
                    return
        except OSError:
            pass
        time.sleep(.25)
    raise RuntimeError('Updated panel did not become ready')

def wait_idle():
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

def safe_install(destination, payload, mode=0o644):
    require(not destination.is_symlink(), 'Unexpected destination symlink')
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name('.' + destination.name + '.multiuser-update')
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(payload)
        os.replace(str(temporary), str(destination))
    finally:
        if temporary.exists():
            temporary.unlink()

try:
    os.umask(0o077)
    record('preflight')
    for path in protected + [data]:
        require(path.is_file() and not path.is_symlink(), 'Unexpected protected configuration')
    require(not registry.exists() and not registry.is_symlink(), 'This first-time release expects no user registry')
    require(not template.exists() and not template.is_symlink(), 'Member service template already exists')
    require(not dropin.exists() and not dropin.is_symlink(), 'Member panel drop-in already exists')
    require(not member_root.exists() and not member_root.is_symlink(), 'Member configuration directory already exists')
    for port in [1443, 2443]:
        stream = socket.socket()
        try:
            stream.bind(('0.0.0.0', port))
        finally:
            stream.close()
    initial_hashes = {str(path): sha(path) for path in protected}
    initial_processes = service_snapshot()
    for name in files:
        candidate = stage / 'release' / name
        require(sha(candidate) == manifest['source_sha256'][name], 'Candidate source hash mismatch')
        if candidate.suffix == '.py':
            py_compile.compile(str(candidate), doraise=True)
        require(not (target / name).is_symlink(), 'Unexpected source symlink')
    require(sha(stage / 'xray-panel@.service') == manifest['template_sha256'], 'Template hash mismatch')
    require(sha(stage / 'multiuser-panel-paths.conf') == manifest['dropin_sha256'], 'Panel drop-in hash mismatch')
    record('linux-candidate-tests')
    environment = os.environ.copy()
    environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
    run([sys.executable, '-m', 'unittest', 'test_configure_reality', 'test_configure_static_exits',
         'panel.test_panel', 'panel.test_routing', 'panel.test_accounts', 'panel.test_multiuser_http'], timeout=240,
        cwd=str(stage / 'release'), env=environment)
    # CentOS 7's systemd-analyze cannot verify an uninstantiated template path.
    # Verify the same bytes under a valid concrete instance name in the stage.
    verify_unit = stage / 'xray-panel@0123456789abcdef.service'
    verify_unit.write_bytes((stage / 'xray-panel@.service').read_bytes())
    os.chmod(str(verify_unit), 0o644)
    run(['systemd-analyze', 'verify', str(verify_unit)], timeout=20)
    require(initial_hashes == {str(path): sha(path) for path in protected}, 'Live configuration changed during tests')
    require(initial_processes == service_snapshot(), 'A protected service restarted during tests')
    record('backup-and-stop-panel')
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
    state_before = data.read_bytes()
    (backup / 'state.private.json').write_bytes(state_before)
    initial_hashes = {str(path): sha(path) for path in protected}
    initial_processes = service_snapshot()
    (backup / 'protected-hashes.json').write_text(json.dumps(initial_hashes, indent=2))
    (backup / 'protected-processes.json').write_text(json.dumps(initial_processes, indent=2))
    require(json.loads(state_before)['managed_hash'] == sha(protected[0]), 'State and administrator config differ')
    record('install-candidate')
    member_root.mkdir(mode=0o700)
    created_member_root = True
    safe_install(template, (stage / 'xray-panel@.service').read_bytes())
    created_template = True
    safe_install(dropin, (stage / 'multiuser-panel-paths.conf').read_bytes())
    created_dropin = True
    for name in files:
        destination = target / name
        require((destination.read_bytes() if destination.exists() else None) == before[name], 'Source changed concurrently')
        safe_install(destination, (stage / 'release' / name).read_bytes())
        installed.append(name)
    run(['systemctl', 'daemon-reload'])
    record('initialize-members')
    sys.path.insert(0, str(target))
    from panel.server import Manager
    from panel.accounts import Accounts
    manager = Manager('/var/lib/vps-panel', '198.200.49.63', Path('/usr/local/etc/xray/config.json'),
                      '/var/lib/vps-panel/base.private.yaml', False,
                      origin='https://198-200-49-63.sslip.io:8443', base_path='/node-console/')
    accounts = Accounts(manager, Path('/var/lib/vps-panel/auth.private.json'), demo=False)
    seeds = json.loads((stage / 'member-seeds.private.json').read_text())
    require(len(seeds) == 2, 'Unexpected member seed count')
    for seed in seeds:
        user = accounts.create_user({key: seed[key] for key in ['username', 'password', 'display_name']})
        require(re.fullmatch(r'[0-9a-f]{16}', user['id']) is not None, 'Unexpected member identity')
        created_ids.append(user['id'])
        result['created_users'].append(user)
    require(sorted(user['port'] for user in result['created_users']) == [1443, 2443], 'Unexpected member ports')
    record('start-and-verify-panel')
    start()
    require(data.read_bytes() == state_before, 'Complete administrator state changed during upgrade')
    require(initial_hashes == {str(path): sha(path) for path in protected}, 'A protected configuration changed')
    require(initial_processes == service_snapshot(), 'A protected service restarted')
    for service in ['vps-panel.service'] + ['xray-panel@' + user_id + '.service' for user_id in created_ids]:
        run(['systemctl', 'is-active', '--quiet', service])
        run(['systemctl', 'is-enabled', '--quiet', service])
    require(registry.is_file() and not registry.is_symlink(), 'User registry missing')
    result.update(success=True, complete_admin_state_preserved=True, protected_hashes_preserved=True,
                  admin_service_processes_preserved=True, existing_admin_account_preserved=True,
                  independent_member_instances=True)
    record('complete')
except BaseException:
    (stage / 'error.private.log').write_text(traceback.format_exc())
    if stopped:
        try:
            run(['systemctl', 'stop', 'vps-panel.service'])
            # Only instances created by this deployment may be removed.
            if registry.exists():
                known = json.loads(registry.read_text())
                entries = known.get('users', [])
                if isinstance(entries, dict):
                    entries = list(entries.values())
                for item in entries:
                    if isinstance(item, dict) and item.get('role') == 'member' and re.fullmatch(r'[0-9a-f]{16}', item.get('id', '')):
                        if item['id'] not in created_ids:
                            created_ids.append(item['id'])
            for user_id in created_ids:
                run(['systemctl', 'stop', 'xray-panel@' + user_id + '.service'], check=False)
                run(['systemctl', 'disable', 'xray-panel@' + user_id + '.service'], check=False)
                for root in [member_root, Path('/var/lib/vps-panel/users')]:
                    destination = root / user_id
                    require(destination.parent == root and not destination.is_symlink(), 'Unsafe rollback member path')
                    if destination.exists():
                        shutil.rmtree(str(destination))
            if registry.exists():
                registry.unlink()
            for name in reversed(installed):
                destination = target / name
                if before[name] is None:
                    destination.unlink()
                else:
                    safe_install(destination, before[name])
            if state_before is not None:
                safe_install(data, state_before, 0o600)
            if created_dropin:
                dropin.unlink()
            if created_template:
                template.unlink()
            if created_member_root and member_root.exists():
                require(not list(member_root.iterdir()), 'Member directory is not empty after rollback')
                member_root.rmdir()
            run(['systemctl', 'daemon-reload'])
            start()
            require(initial_hashes == {str(path): sha(path) for path in protected}, 'Protected configuration changed after rollback')
            require(initial_processes == service_snapshot(), 'Protected services changed after rollback')
            result['rolled_back'] = True
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result.update(rolled_back=False, rollback_failed=True)
    record('failed')
    print(json.dumps(result))
    sys.exit(1)
print(json.dumps(result))
'''


def member_seeds():
    path = FOLDER / 'multiuser-member-seeds.private.json'
    if path.exists():
        values = json.loads(path.read_text(encoding='utf-8'))
        live.require(isinstance(values, list) and len(values) == 2 and
                     [value.get('username') for value in values] == ['user-a', 'user-b'] and
                     all(isinstance(value.get('password'), str) and len(value['password']) >= 24 for value in values),
                     'Existing member seed file is invalid')
        return path, values
    values = [{'username': 'user-a', 'display_name': '用户 A', 'password': secrets.token_urlsafe(24)},
              {'username': 'user-b', 'display_name': '用户 B', 'password': secrets.token_urlsafe(24)}]
    path.write_text(json.dumps(values, indent=2, ensure_ascii=False), encoding='utf-8')
    return path, values


def deploy(manifest):
    login = json.loads((FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
    status, headers, _ = live.request('POST', 'api/login', {'username': login['username'], 'password': login['password']})
    live.require(status == 200, 'Could not authenticate the read-only deployment preflight')
    session_path = FOLDER / 'multiuser-update-session.private.json'
    session_path.write_text(json.dumps({'cookie': headers['Set-Cookie'].split(';', 1)[0]}), encoding='utf-8')
    seeds_path, seeds = member_seeds()
    stage = '/root/raksmart-proxy-deploy-20261009/multiuser-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3)
    client = connect()
    try:
        code, _, _ = execute(client, 'install -d -m 0700 ' + shlex.quote(stage))
        live.require(code == 0, 'Could not create private deployment stage')
        with client.open_sftp() as sftp:
            for local, remote in [(ARCHIVE, 'release.tar.gz'), (MANIFEST, 'manifest.json'),
                                  (session_path, 'session.private.json'), (seeds_path, 'member-seeds.private.json')]:
                sftp.put(str(local), stage + '/' + remote)
                sftp.chmod(stage + '/' + remote, 0o600)
        program = 'STAGE = ' + repr(stage) + '\n' + PROGRAM
        command = ('set -eu\ncd ' + shlex.quote(stage) + '\n' +
                   'printf ' + shlex.quote('%s  release.tar.gz\n') + ' ' + shlex.quote(manifest['archive_sha256']) +
                   ' | sha256sum --check --status\ntar -xzf release.tar.gz\n' +
                   "python3 - <<'MULTIUSER_UPDATE'\n" + program + '\nMULTIUSER_UPDATE\n')
        code, output, error = execute(client, command, timeout=390)
        (FOLDER / 'multiuser-update.private.log').write_text(output + '\n' + error, encoding='utf-8')
        with client.open_sftp() as sftp:
            sftp.get(stage + '/update-state.json', str(REPORT))
            for remote, local in [('commands.private.log', 'multiuser-commands.private.log'),
                                  ('error.private.log', 'multiuser-remote-error.private.log'),
                                  ('rollback-error.private.log', 'multiuser-rollback-error.private.log')]:
                try:
                    sftp.stat(stage + '/' + remote)
                except OSError:
                    continue
                sftp.get(stage + '/' + remote, str(FOLDER / local))
        result = json.loads(REPORT.read_text(encoding='utf-8'))
        live.require(code == 0 and result.get('success'), 'Multi-user release failed; inspect the private update logs and report')
        for seed in seeds:
            user = next(user for user in result['created_users'] if user['username'] == seed['username'])
            record = dict(seed, url=ORIGIN + '/node-console/', id=user['id'], port=user['port'])
            (FOLDER / ('multiuser-' + seed['username'] + '-login.private.json')).write_text(
                json.dumps(record, indent=2, ensure_ascii=False), encoding='utf-8')
        for name in FILES:
            shutil.copyfile(str(RELEASE / name), str(FOLDER / 'panel-release' / name))
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
        print(json.dumps({'prepared': True, 'files': manifest['files'], 'python_syntax': '3.6',
                          'archive_sha256': manifest['archive_sha256']}))
    else:
        deploy(frozen_manifest())
