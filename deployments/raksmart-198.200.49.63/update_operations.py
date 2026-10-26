"""Prepare a reversible operations upgrade for the existing three-user node.

--prepare-only is strictly local. Publishing requires this frozen manifest and
preserves account identities while adding read-only loopback Xray statistics.
The root agent reviews this publisher and performs all remote actions.
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
from multiuser_update import compatible
from update_routing_url import login_sessions, logout_sessions


ROOT = FOLDER.parents[1]
FILES = ["panel/server.py", "panel/accounts.py", "panel/subscriptions.py", "panel/audit.py",
         "panel/diagnostics.py", "panel/health.py", "panel/telemetry.py", "panel/backups.py",
         "panel/test_panel.py", "panel/test_accounts.py", "panel/test_subscriptions.py",
         "panel/test_multiuser_http.py", "panel/test_operations.py", "panel/test_enhancements_http.py",
         "panel/web/style.css", "panel/web/app.js", "panel/web/index.html"]
WHEEL_NAMES = ["cryptography-3.3.2-cp36-abi3-manylinux2010_x86_64.whl",
               "cffi-1.15.1-cp36-cp36m-manylinux_2_5_x86_64.manylinux1_x86_64.whl",
               "pycparser-2.21-py2.py3-none-any.whl", "six-1.17.0-py2.py3-none-any.whl",
               "pip-21.3.1-py3-none-any.whl"]
RELEASE = FOLDER / "operations-release"
ARCHIVE = FOLDER / "operations-release.tar.gz"
MANIFEST = FOLDER / "operations-release-manifest.json"
REPORT = FOLDER / "operations-update.json"
VERIFY_REPORT = FOLDER / "operations-verification.json"
PLAN = FOLDER / "operations-release-plan.json"
PREFIX = "/root/raksmart-proxy-deploy-20261009/operations-"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_file(path):
    return (path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts
            and path.suffix != ".pyc" and ".private." not in path.name)


def prepare():
    baseline = FOLDER / "panel-release"
    live.require(baseline.is_dir() and not baseline.is_symlink(), "Compatible deployed baseline is missing")
    baseline_names = sorted(path.relative_to(baseline).as_posix()
                            for path in baseline.rglob("*") if clean_file(path))
    live.require("configure_reality.py" in baseline_names and "panel/accounts.py" in baseline_names,
                 "Existing node adoption baseline is incomplete")
    if RELEASE.exists():
        live.require(RELEASE.resolve().parent == FOLDER.resolve() and RELEASE.name == "operations-release"
                     and not RELEASE.is_symlink(), "Unsafe local staging directory")
        shutil.rmtree(str(RELEASE))
    RELEASE.mkdir()
    baseline_hashes = {}
    for name in baseline_names:
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((baseline / name).read_bytes())
        baseline_hashes[name] = sha(baseline / name)
    for name in FILES:
        source = ROOT / name
        live.require(clean_file(source), "A requested source is unavailable: " + name)
        text = source.read_text(encoding="utf-8")
        if name == "panel/test_panel.py":
            old = (baseline / name).read_text(encoding="utf-8")
            marker = "class ExistingRaksmartNodeTests"
            live.require(marker in old and "class PanelTests" in old, "Existing-node adoption tests are missing")
            adoption = old.split(marker, 1)[1].split("class PanelTests", 1)[0]
            # The original identity must remain identical while the new primary
            # statistics label is explicitly allowed and verified separately.
            legacy_assertion = ('        self.assertEqual(extended["inbounds"][0]["settings"]["clients"][0],\n'
                                '                         self.original["inbounds"][0]["settings"]["clients"][0])')
            updated_assertion = ('        primary = extended["inbounds"][0]["settings"]["clients"][0]\n'
                                 '        self.assertEqual({key: value for key, value in primary.items() if key != "email"},\n'
                                 '                         self.original["inbounds"][0]["settings"]["clients"][0])\n'
                                 '        self.assertEqual(primary["email"], "panel-primary@stats.invalid")\n'
                                 '        self.assertEqual(len(extended["inbounds"]), 1)\n'
                                 '        self.assertEqual(extended["api"], {"tag": "panel-stats-api",\n'
                                 '                         "listen": "127.0.0.1:15443", "services": ["StatsService"]})')
            if legacy_assertion in adoption:
                adoption = adoption.replace(legacy_assertion, updated_assertion, 1)
            live.require(updated_assertion in adoption, "Adoption statistics and identity assertions are incomplete")
            live.require(marker not in text, "Adoption tests were already inserted into the raw source")
            text = "import base64\n" + text.replace("class PanelTests", marker + adoption + "class PanelTests", 1)
        if name.endswith(".py"):
            text = compatible(text, name)
            ast.parse(text, filename=name, feature_version=(3, 6))
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    names = sorted(set(baseline_names) | set(FILES))
    for name in names:
        if name.endswith(".py"):
            ast.parse((RELEASE / name).read_text(encoding="utf-8"), filename=name, feature_version=(3, 6))
    live.require((RELEASE / "configure_reality.py").read_bytes() == (baseline / "configure_reality.py").read_bytes(),
                 "The existing configure_reality adapter changed")
    subprocess.run(["node", "--check", str(RELEASE / "panel/web/app.js")], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, creationflags=live.NO_WINDOW)
    ast.parse(PROGRAM, filename="operations_remote_update.py", feature_version=(3, 6))
    wheel_hashes = {}
    for name in WHEEL_NAMES:
        path = FOLDER / "operations-wheels" / name
        live.require(clean_file(path), "A predownloaded Linux Python 3.6 wheel is missing")
        wheel_hashes[name] = sha(path)
    with tarfile.open(str(ARCHIVE), "w:gz") as bundle:
        for name in names:
            bundle.add(str(RELEASE / name), arcname="release/" + name, recursive=False)
        for name in WHEEL_NAMES:
            bundle.add(str(FOLDER / "operations-wheels" / name), arcname="wheels/" + name, recursive=False)
    manifest = {"deployment_ip": live.IP, "files": FILES, "release_files": names,
                "prepared_at": datetime.now(timezone.utc).isoformat(), "archive_sha256": sha(ARCHIVE),
                "source_sha256": {name: sha(RELEASE / name) for name in FILES},
                "release_sha256": {name: sha(RELEASE / name) for name in names},
                "baseline_sha256": baseline_hashes,
                "new_files": sorted(set(FILES) - set(baseline_names)),
                "wheel_sha256": wheel_hashes, "python_syntax": "3.6",
                "remote_program_sha256": hashlib.sha256(PROGRAM.encode("utf-8")).hexdigest(),
                "configure_reality_adapter_preserved": True,
                "configuration_migration": "private statistics only; existing identities and histories retained"}
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    PLAN.write_text(json.dumps({"prepared": True, "deployment_executed": False,
        "changed_source_files": FILES, "new_source_files": manifest["new_files"],
        "offline_dependency": "cryptography 3.3.2 and three frozen dependencies, isolated vendor directory",
        "mutable_existing_data": "managed_hash and subscription metadata only; read-only statistics in proxy config",
        "service_changes": "restart panel and each enabled proxy sequentially; disabled members stay stopped",
        "unchanged_services": ["caddy.service", "raksmart-hy2.service"],
        "dropin": "append CAP_NET_ADMIN, CAP_NET_RAW and AF_NETLINK; preserve existing writable paths",
        "rollback": "compare expected installed bytes before restoring source/config/state/vendor/dropin",
        "archive_sha256": manifest["archive_sha256"]}, indent=2), encoding="utf-8")
    return manifest


def frozen_manifest():
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    live.require(manifest.get("deployment_ip") == live.IP and manifest.get("files") == FILES,
                 "Unexpected frozen operations release")
    live.require(sha(ARCHIVE) == manifest["archive_sha256"]
                 and hashlib.sha256(PROGRAM.encode("utf-8")).hexdigest() == manifest["remote_program_sha256"],
                 "Frozen archive or publisher changed")
    for name in manifest["release_files"]:
        live.require(isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts,
                     "Unsafe frozen source path")
        live.require(sha(RELEASE / name) == manifest["release_sha256"][name], "Frozen source changed")
    for name in WHEEL_NAMES:
        live.require(sha(FOLDER / "operations-wheels" / name) == manifest["wheel_sha256"][name],
                     "Frozen wheel changed")
    return manifest


PROGRAM = r'''
import copy, hashlib, json, os, py_compile, re, shutil, socket, stat, subprocess, sys, tarfile, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
registry = Path('/var/lib/vps-panel/users.private.json')
dropin = Path('/etc/systemd/system/vps-panel.service.d/operations.conf')
manifest = json.loads((stage / 'manifest.json').read_text())
files = manifest['files']
expected_files = ['panel/server.py', 'panel/accounts.py', 'panel/subscriptions.py', 'panel/audit.py',
                  'panel/diagnostics.py', 'panel/health.py', 'panel/telemetry.py', 'panel/backups.py',
                  'panel/test_panel.py', 'panel/test_accounts.py', 'panel/test_subscriptions.py',
                  'panel/test_multiuser_http.py', 'panel/test_operations.py', 'panel/test_enhancements_http.py',
                  'panel/web/style.css', 'panel/web/app.js', 'panel/web/index.html']
result = {'success': False, 'phase': 'preflight', 'deployment_ip': '198.200.49.63',
          'updated_files': files, 'stage': str(stage), 'backup': str(stage / 'before'),
          'proxy_restarts': [], 'identity_preserved': False, 'caddy_hy2_preserved': False}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, indent=2).encode('utf-8') + b'\n'

def private_json(path, value):
    path.write_bytes(json_bytes(value))
    os.chmod(str(path), 0o600)

def record(phase):
    result['phase'] = phase
    private_json(stage / 'update-state.json', result)

def run(args, timeout=30, cwd=None, env=None):
    response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=cwd, env=env)
    with (stage / 'commands.private.log').open('ab') as stream:
        stream.write(response.stdout + b'\n' + response.stderr)
    require(response.returncode == 0, 'Command failed during ' + result['phase'] + ': ' + Path(args[0]).name)
    return response

def attributes(path):
    info = path.stat()
    return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}

def service_snapshot(service):
    raw = run(['systemctl', 'show', service]).stdout.decode()
    fields = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    keys = ['ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'ActiveEnterTimestampMonotonic',
            'ExecMainStartTimestampMonotonic', 'NRestarts']
    require(all(key in fields for key in keys[:6]), 'Service snapshot is incomplete')
    return {key: fields[key] for key in keys if key in fields}

def inventory():
    require(registry.is_file() and not registry.is_symlink(), 'Existing account registry is missing')
    data = json.loads(registry.read_text())
    require(data.get('version') == 1 and isinstance(data.get('users'), list) and len(data['users']) <= 2,
            'Unexpected member registry')
    ids, ports = set(), set()
    users = [{'id': 'admin', 'port': 443, 'enabled': True,
              'state': '/var/lib/vps-panel/state.private.json',
              'config': '/usr/local/etc/xray/config.json', 'service': 'xray.service'}]
    for user in data['users']:
        identity, port = user.get('id'), user.get('port')
        require(isinstance(identity, str) and re.fullmatch(r'[a-f0-9]{16}', identity)
                and identity not in ids and type(port) is int and port in [1443, 2443]
                and port not in ports and user.get('role') == 'member' and type(user.get('enabled')) is bool,
                'Unexpected member identity')
        ids.add(identity)
        ports.add(port)
        users.append({'id': identity, 'port': port, 'enabled': user['enabled'],
                      'state': '/var/lib/vps-panel/users/' + identity + '/state.private.json',
                      'config': '/usr/local/etc/xray-members/' + identity + '/config.json',
                      'service': 'xray-panel@' + identity + '.service'})
    return users

def protected_paths():
    paths = [registry, Path('/var/lib/vps-panel/auth.private.json'), Path('/var/lib/vps-panel/base.private.yaml'),
             Path('/usr/local/etc/raksmart-hy2/server.yaml'), Path('/etc/caddy/Caddyfile'), Path('/etc/resolv.conf'),
             Path('/etc/systemd/system/xray.service'), Path('/etc/systemd/system/xray-panel@.service'),
             Path('/etc/systemd/system/vps-panel.service'), Path('/etc/systemd/system/caddy.service'),
             Path('/etc/systemd/system/raksmart-hy2.service')]
    paths.extend(target / name for name in manifest['baseline_sha256'] if name not in files)
    for service in ['vps-panel.service', 'xray.service', 'xray-panel@.service', 'caddy.service', 'raksmart-hy2.service']:
        directory = Path('/etc/systemd/system') / (service + '.d')
        if directory.exists():
            require(not directory.is_symlink(), 'Service drop-in directory is a symlink')
            paths.extend(path for path in directory.glob('*.conf') if path != dropin)
    for user in inventory()[1:]:
        directory = Path('/etc/systemd/system') / (user['service'] + '.d')
        if directory.exists():
            require(not directory.is_symlink(), 'Member service drop-in directory is a symlink')
            paths.extend(directory.glob('*.conf'))
    return sorted(set(paths))

def snapshot():
    paths = protected_paths()
    for path in paths:
        require(path.is_file() and not path.is_symlink(), 'A protected file is unavailable or unsafe')
    users = inventory()
    configs, states, services = {}, {}, {}
    for user in users:
        state_path, config_path = Path(user['state']), Path(user['config'])
        for path in [state_path, config_path]:
            require(path.is_file() and not path.is_symlink() and not path.parent.is_symlink(), 'Unsafe account file')
        state = json.loads(state_path.read_text())
        require(state.get('managed_hash') == sha(config_path), 'An account config and state differ')
        require(state['base']['inbounds'][0]['port'] == user['port'], 'An account entrance port changed')
        configs[user['id']] = {'sha256': sha(config_path), 'attributes': attributes(config_path)}
        states[user['id']] = {'sha256': sha(state_path), 'attributes': attributes(state_path)}
        services[user['service']] = service_snapshot(user['service'])
        require((services[user['service']]['ActiveState'] == 'active') == user['enabled'],
                'An account service state differs from its enabled state')
    directories = [Path('/var/lib/vps-panel'), Path('/var/lib/vps-panel/users'), Path('/usr/local/etc/xray-members')]
    directories.extend(Path(user[key]).parent for user in users for key in ['state', 'config'])
    for path in directories:
        require(path.is_dir() and not path.is_symlink(), 'Unsafe account directory')
    return {'users': users, 'protected_sha256': {str(path): sha(path) for path in paths},
            'protected_attributes': {str(path): attributes(path) for path in paths},
            'directory_attributes': {str(path): attributes(path) for path in set(directories)},
            'configs': configs, 'states': states, 'proxy_services': services,
            'unchanged_services': {service: service_snapshot(service)
                                   for service in ['caddy.service', 'raksmart-hy2.service']}}

def stable_preservation(before):
    after = snapshot()
    expected_hashes = dict(before['protected_sha256'])
    supplement = stage / 'backup-upload-supplement.json'
    if supplement.exists():
        require(supplement.is_file() and not supplement.is_symlink(), 'Unsafe backup ingress supplement')
        adjustment = json.loads(supplement.read_text())
        caddy_path = '/etc/caddy/Caddyfile'
        require(adjustment.get('success') is True and adjustment.get('scope') == 'backup_preview_ingress_only'
                and adjustment.get('caddy_before_sha256') == expected_hashes[caddy_path]
                and adjustment.get('services_restarted') is False
                and adjustment.get('caddy_process_preserved') is True,
                'Unreviewed Caddy ingress adjustment')
        expected_hashes[caddy_path] = adjustment['caddy_after_sha256']
        result['backup_preview_ingress_updated'] = True
    require(after['protected_sha256'] == expected_hashes, 'Protected source or configuration changed')
    for key in ['users', 'protected_attributes', 'directory_attributes', 'unchanged_services']:
        require(after[key] == before[key], 'Protected ' + key + ' changed')
    for key in ['configs', 'states']:
        require({identity: item['attributes'] for identity, item in after[key].items()}
                == {identity: item['attributes'] for identity, item in before[key].items()}, 'Account file permissions changed')
    for user in before['users']:
        current = after['proxy_services'][user['service']]
        old = before['proxy_services'][user['service']]
        for key in ['ActiveState', 'SubState', 'UnitFileState']:
            require(current[key] == old[key], 'Account service enablement changed')
        if not user['enabled']:
            require(current == old, 'A disabled account service changed')
    return after

def wait_idle():
    sessions = json.loads((stage / 'sessions.private.json').read_text())
    enabled = {user['id'] for user in inventory() if user['enabled']}
    require(set(sessions) == enabled, 'Enabled preflight sessions are incomplete')
    deadline = time.monotonic() + 45
    while True:
        idle = True
        for identity, token in sessions.items():
            request = Request('http://127.0.0.1:18787/api/state', headers={'Cookie': token['cookie']})
            with urlopen(request, timeout=4) as response:
                state = json.loads(response.read().decode())
            require(state.get('server_ip') == '198.200.49.63' and state.get('user', {}).get('id') == identity,
                    'A preflight session identifies another user')
            idle = idle and (state.get('job') or {}).get('status') != 'running'
        if idle:
            return
        require(time.monotonic() < deadline, 'An account operation is still running')
        time.sleep(.4)

def atomic(path, payload, info):
    require(not path.is_symlink(), 'Unexpected destination symlink')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.operations-' + stage.name[-6:])
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), info['mode'])
            os.fchown(stream.fileno(), info['uid'], info['gid'])
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()

def safe_extract():
    require(sha(stage / 'release.tar.gz') == manifest['archive_sha256'], 'Frozen archive changed')
    names = manifest['release_files']
    expected = {'release/' + name for name in names} | {'wheels/' + name for name in manifest['wheel_sha256']}
    require(len(names) == len(set(names)) and set(manifest['release_sha256']) == set(names)
            and set(files).issubset(names), 'Invalid release inventory')
    for name in names:
        require(isinstance(name, str) and not name.startswith('/') and '\\' not in name
                and '..' not in Path(name).parts and '.private.' not in name, 'Unsafe release path')
    with tarfile.open(str(stage / 'release.tar.gz'), 'r:gz') as bundle:
        entries = bundle.getmembers()
        require(len(entries) == len(expected) and {entry.name for entry in entries} == expected
                and all(entry.isfile() for entry in entries) and sum(entry.size for entry in entries) < 30000000,
                'Unexpected archive content')
        for entry in entries:
            destination = stage / entry.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.extractfile(entry) as source, destination.open('xb') as output:
                output.write(source.read())
            os.chmod(str(destination), 0o600)
    for name in names:
        require(sha(stage / 'release' / name) == manifest['release_sha256'][name], 'Candidate source hash changed')
        destination = target / name
        if name in manifest['baseline_sha256']:
            require(destination.is_file() and not destination.is_symlink()
                    and sha(destination) == manifest['baseline_sha256'][name], 'Deployed baseline source changed')
        else:
            require(not destination.exists() and not destination.is_symlink(), 'A proposed new source already exists')
        if name not in files:
            require(manifest['release_sha256'][name] == manifest['baseline_sha256'][name], 'Unchanged adapter source changed')
        if name.endswith('.py'):
            py_compile.compile(str(stage / 'release' / name), doraise=True)
    for name, expected_hash in manifest['wheel_sha256'].items():
        require(re.fullmatch(r'[A-Za-z0-9_.-]+\.whl', name) and sha(stage / 'wheels' / name) == expected_hash,
                'Frozen dependency wheel changed')

def vendor_prepare():
    pip_wheel = stage / 'wheels/pip-21.3.1-py3-none-any.whl'
    require(pip_wheel.is_file(), 'The offline Python 3.6 pip bootstrap is missing')
    env = os.environ.copy()
    env['PYTHONPATH'] = str(pip_wheel)
    args = [sys.executable, '-m', 'pip', 'install', '--no-index', '--no-deps', '--disable-pip-version-check',
            '--target', str(stage / 'vendor')]
    args.extend(str(stage / 'wheels' / name) for name in sorted(manifest['wheel_sha256']) if name != pip_wheel.name)
    run(args, timeout=90, env=env)
    env['PYTHONPATH'] = str(stage / 'vendor')
    run([sys.executable, '-c', 'import cryptography; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; '
         'assert cryptography.__version__ == "3.3.2"; k=AESGCM.generate_key(bit_length=256); a=AESGCM(k); '
         'n=b"0"*12; assert a.decrypt(n,a.encrypt(n,b"test",b"meta"),b"meta")==b"test"'], env=env)

def vendor_hashes(directory):
    require(directory.is_dir() and not directory.is_symlink(), 'Unsafe vendor directory')
    hashes = {}
    for path in directory.rglob('*'):
        require(not path.is_symlink(), 'A vendor entry is a symlink')
        if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc':
            hashes[path.relative_to(directory).as_posix()] = sha(path)
    return hashes

def start_panel():
    run(['systemctl', 'start', 'vps-panel.service'])
    for attempt in range(60):
        try:
            with urlopen('http://127.0.0.1:18787/api/session', timeout=1) as response:
                if response.status == 200 and not json.loads(response.read().decode())['authenticated']:
                    run(['systemctl', 'is-active', '--quiet', 'vps-panel.service'])
                    return
        except OSError:
            pass
        time.sleep(.25)
    raise RuntimeError('The operations worker did not become ready')

def wait_proxy(user):
    for attempt in range(40):
        state = service_snapshot(user['service'])
        if state['ActiveState'] == 'active':
            try:
                with socket.create_connection(('127.0.0.1', user['port']), timeout=.4):
                    return
            except OSError:
                pass
        time.sleep(.25)
    raise RuntimeError('An isolated proxy failed its local listener check')

def backup_entry(path, expected_after, info=None):
    exists = path.exists()
    require(not path.is_symlink(), 'A transactional destination is a symlink')
    logical = str(path).lstrip('/')
    if exists:
        require(path.is_file(), 'A transactional file destination is not a file')
        destination = stage / 'before/files' / logical
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes())
        os.chmod(str(destination), 0o600)
    return {'path': str(path), 'existed': exists, 'backup': logical,
            'before_sha256': sha(path) if exists else None,
            'after_sha256': hashlib.sha256(expected_after).hexdigest(),
            'attributes': attributes(path) if exists else (info or {'mode': 0o644, 'uid': 0, 'gid': 0})}

def migration_candidates(before):
    sys.path.insert(0, str(stage / 'release'))
    from panel.telemetry import augment_config, validate_augmentation
    from panel.subscriptions import ensure_metadata
    mutations = []
    for user in before['users']:
        state_path, config_path = Path(user['state']), Path(user['config'])
        old_state = json.loads(state_path.read_text())
        old_config = json.loads(config_path.read_text())
        candidate = augment_config(old_config, user['port'])
        validate_augmentation(candidate, allow_legacy=False)
        require(candidate.get('outbounds') == old_config.get('outbounds')
                and candidate.get('routing') == old_config.get('routing'), 'Statistics migration changed egress routing')
        old_inbound, new_inbound = old_config['inbounds'][0], candidate['inbounds'][0]
        require(new_inbound.get('streamSettings') == old_inbound.get('streamSettings'),
                'Statistics migration changed REALITY keys or connection settings')
        old_clients = old_inbound['settings']['clients']
        new_clients = new_inbound['settings']['clients']
        require(len(old_clients) == len(new_clients), 'Statistics migration changed proxy identity count')
        for original_client, changed_client in zip(old_clients, new_clients):
            original_identity, changed_identity = copy.deepcopy(original_client), copy.deepcopy(changed_client)
            if not original_identity.get('email'):
                original_identity.pop('email', None)
                changed_identity.pop('email', None)
            require(original_identity == changed_identity, 'Statistics migration changed a proxy identity')
        payload = json_bytes(candidate)
        state = copy.deepcopy(old_state)
        ensure_metadata(state)
        state['managed_hash'] = hashlib.sha256(payload).hexdigest()
        # Every pre-existing field except managed_hash remains equal, including
        # UUIDs, REALITY keys, rule capabilities, routing, profiles and history.
        for key, value in old_state.items():
            if key not in ['managed_hash', 'profile_token', 'profile_version', 'profile_hash', 'profile_updated']:
                require(state[key] == value, 'Migration replaced an existing account field')
        cfg_candidate = stage / ('candidate-' + user['id'] + '.private.json')
        cfg_candidate.write_bytes(payload)
        os.chmod(str(cfg_candidate), 0o600)
        run(['/usr/local/bin/xray', 'run', '-test', '-config', str(cfg_candidate)])
        mutations.extend([(config_path, payload), (state_path, json_bytes(state))])
    return mutations

def assets_verified():
    for name, resource in [('panel/web/index.html', '/'), ('panel/web/app.js', '/app.js'), ('panel/web/style.css', '/style.css')]:
        with urlopen('http://127.0.0.1:18787' + resource, timeout=5) as response:
            require(response.status == 200 and hashlib.sha256(response.read()).hexdigest() == manifest['source_sha256'][name],
                    'A served browser source differs from the frozen release')
            require('no-store' in response.headers.get('Cache-Control', ''), 'Browser source cache policy changed')

def installed_verified(before, journal):
    after = stable_preservation(before)
    for entry in journal:
        path = Path(entry['path'])
        require(path.is_file() and not path.is_symlink() and sha(path) == entry['after_sha256'],
                'Installed source/config/state differs from the transaction')
    transaction = json.loads((stage / 'transaction.private.json').read_text())
    require(vendor_hashes(target / 'vendor') == transaction['vendor_after_sha256'], 'Installed dependency source changed')
    for user in before['users']:
        if user['enabled']:
            wait_proxy(user)
            raw = run(['/usr/local/bin/xray', 'api', 'statsquery',
                       '--server=127.0.0.1:' + str(15000 + user['port']), '-pattern', 'user>>>']).stdout.decode()
            begin, end = raw.find('{'), raw.rfind('}')
            require(begin >= 0 and end >= begin and isinstance(json.loads(raw[begin:end + 1]), dict),
                    'A private statistics API is not readable')
    assets_verified()
    return after

def rollback():
    before = json.loads((stage / 'before/snapshot.private.json').read_text())
    transaction = json.loads((stage / 'transaction.private.json').read_text())
    run(['systemctl', 'stop', 'vps-panel.service'])
    # Establish the complete comparison before the first restore; preserve any
    # account changes made after publishing instead of overwriting them.
    restore_entries = []
    for entry in transaction['installed']:
        path = Path(entry['path'])
        require(not path.is_symlink(), 'A destination symlink prevents transaction rollback')
        if not entry['existed'] and not path.exists():
            continue
        require(path.is_file(), 'A transactional destination is missing')
        actual = sha(path)
        if entry['existed'] and actual == entry['before_sha256']:
            continue
        require(actual == entry['after_sha256'], 'A concurrent change prevents automatic transaction rollback')
        restore_entries.append(entry)
    vendor = target / 'vendor'
    old_vendor = stage / 'before/vendor'
    if transaction.get('vendor_install_started'):
        if vendor.exists():
            expected_vendor = (transaction['vendor_before_sha256'] if transaction['vendor_existed']
                               and not old_vendor.exists() and not transaction.get('vendor_installed')
                               else transaction['vendor_after_sha256'])
            require(vendor_hashes(vendor) == expected_vendor, 'A dependency change prevents transaction rollback')
        if old_vendor.exists():
            require(vendor_hashes(old_vendor) == transaction['vendor_before_sha256'], 'The original vendor backup changed')
    for entry in reversed(restore_entries):
        path = Path(entry['path'])
        if entry['existed']:
            atomic(path, (stage / 'before/files' / entry['backup']).read_bytes(), entry['attributes'])
        else:
            path.unlink()
    if transaction.get('vendor_install_started'):
        if vendor.exists() and (old_vendor.exists() or not transaction['vendor_existed']):
            require(vendor.is_dir() and not vendor.is_symlink() and vendor.resolve().parent == target.resolve(),
                    'Unsafe vendor rollback target')
            os.replace(str(vendor), str(stage / 'vendor-rolled-back'))
        if old_vendor.exists():
            require(not vendor.exists() and not old_vendor.is_symlink(), 'Vendor restore destination changed')
            os.replace(str(old_vendor), str(vendor))
    run(['systemctl', 'daemon-reload'])
    for user in before['users']:
        if user['service'] in transaction['restarted']:
            run(['systemctl', 'restart', user['service']])
            wait_proxy(user)
    start_panel()
    after = stable_preservation(before)
    require(after['configs'] == before['configs'] and after['states'] == before['states'],
            'Rollback did not restore original account bytes')
    result.update(success=False, source_rollback_succeeded=True, configuration_rollback_succeeded=True,
                  identity_preserved=True, caddy_hy2_preserved=True, phase='rolled-back')
    private_json(stage / 'update-state.json', result)

try:
    os.umask(0o077)
    require(manifest.get('deployment_ip') == '198.200.49.63' and files == expected_files
            and set(files) == set(manifest['source_sha256']), 'Unexpected target or source scope')
    if ACTION == 'install':
        record('preflight')
        run(['systemctl', 'is-active', '--quiet', 'vps-panel.service'])
        run(['systemctl', 'is-enabled', '--quiet', 'vps-panel.service'])
        safe_extract()
        initial = snapshot()
        wait_idle()
        record('offline-dependencies')
        vendor_prepare()
        record('candidate-tests')
        environment = os.environ.copy()
        environment['PYTHONPATH'] = str(stage / 'vendor')
        environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
        run([sys.executable, '-m', 'unittest', 'test_configure_reality', 'test_configure_static_exits',
             'panel.test_panel', 'panel.test_routing', 'panel.test_accounts', 'panel.test_multiuser_http',
             'panel.test_subscriptions', 'panel.test_operations', 'panel.test_enhancements_http'],
            timeout=300, cwd=str(stage / 'release'), env=environment)
        require(snapshot() == initial, 'An account changed during candidate tests')
        wait_idle()
        record('stop-panel')
        run(['systemctl', 'stop', 'vps-panel.service'])
        before = snapshot()
        require(before == initial, 'An operation raced the panel stop')
        (stage / 'before').mkdir(mode=0o700)
        private_json(stage / 'before/snapshot.private.json', before)
        transaction = {'installed': [], 'restarted': [], 'vendor_installed': False,
                       'vendor_install_started': False, 'vendor_existed': False}
        private_json(stage / 'transaction.private.json', transaction)
        record('validate-statistics-migration')
        mutations = migration_candidates(before)
        for name in files:
            mutations.append((target / name, (stage / 'release' / name).read_bytes()))
        require(not dropin.is_symlink() and (not dropin.exists() or dropin.is_file()), 'Unsafe operations drop-in')
        previous_dropin = dropin.read_bytes() if dropin.exists() else b''
        mutations.append((dropin, previous_dropin + b'\n[Service]\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\nRestrictAddressFamilies=AF_NETLINK\n'))
        journal = [backup_entry(path, payload) for path, payload in mutations]
        private_json(stage / 'planned-mutations.private.json', journal)
        record('install-reviewed-transaction')
        for (path, payload), entry in zip(mutations, journal):
            if entry['existed']:
                require(sha(path) == entry['before_sha256'], 'A destination changed concurrently')
            else:
                require(not path.exists() and not path.is_symlink(), 'A new destination appeared concurrently')
            transaction['installed'].append(entry)
            private_json(stage / 'transaction.private.json', transaction)
            atomic(path, payload, entry['attributes'])
        vendor = target / 'vendor'
        require(not vendor.is_symlink(), 'Existing vendor directory is a symlink')
        transaction['vendor_existed'] = vendor.exists()
        transaction['vendor_before_sha256'] = vendor_hashes(vendor) if vendor.exists() else {}
        transaction['vendor_after_sha256'] = vendor_hashes(stage / 'vendor')
        transaction['vendor_install_started'] = True
        private_json(stage / 'transaction.private.json', transaction)
        if vendor.exists():
            require(vendor.is_dir(), 'Existing vendor destination is not a directory')
            os.replace(str(vendor), str(stage / 'before/vendor'))
        os.replace(str(stage / 'vendor'), str(vendor))
        transaction['vendor_installed'] = True
        private_json(stage / 'transaction.private.json', transaction)
        run(['systemctl', 'daemon-reload'])
        record('restart-private-proxies')
        for user in before['users']:
            if user['enabled']:
                transaction['restarted'].append(user['service'])
                private_json(stage / 'transaction.private.json', transaction)
                run(['systemctl', 'restart', user['service']])
                wait_proxy(user)
                result['proxy_restarts'].append(user['service'])
                record('restart-private-proxies')
        record('start-panel')
        start_panel()
        installed_verified(before, transaction['installed'])
        result.update(candidate_installed=True, local_acceptance=True, identity_preserved=True,
                      caddy_hy2_preserved=True, disabled_members_preserved=True, phase='pending-public-acceptance')
        private_json(stage / 'update-state.json', result)
    elif ACTION in ['finalize', 'verify']:
        result = json.loads((stage / 'update-state.json').read_text())
        before = json.loads((stage / 'before/snapshot.private.json').read_text())
        transaction = json.loads((stage / 'transaction.private.json').read_text())
        installed_verified(before, transaction['installed'])
        result.update(success=True, phase='complete' if ACTION == 'finalize' else 'verified',
                      public_assets_verified=True, identity_preserved=True, caddy_hy2_preserved=True)
        private_json(stage / ('verify-state.json' if ACTION == 'verify' else 'update-state.json'), result)
    elif ACTION == 'rollback':
        result = json.loads((stage / 'update-state.json').read_text())
        rollback()
    else:
        raise RuntimeError('Unsupported operations action')
except BaseException:
    (stage / (ACTION + '-error.private.log')).write_text(traceback.format_exc())
    if ACTION == 'install' and (stage / 'transaction.private.json').is_file():
        try:
            rollback()
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result.update(rollback_failed=True, source_rollback_succeeded=False, configuration_rollback_succeeded=False)
    elif ACTION == 'install' and result.get('phase') == 'stop-panel':
        try:
            start_panel()
        except BaseException:
            result['panel_recovery_failed'] = True
    result.update(success=False, phase='failed')
    private_json(stage / ('verify-state.json' if ACTION == 'verify' else 'update-state.json'), result)
    print(json.dumps(result))
    sys.exit(1)
print(json.dumps(result))
'''


def remote_action(client, stage, action):
    live.require(action in ("install", "finalize", "verify", "rollback"), "Unsupported operations action")
    live.require(re.fullmatch(re.escape(PREFIX) + r"[0-9]{8}T[0-9]{6}-[a-f0-9]{6}", stage), "Unsafe remote stage")
    program = "STAGE = " + repr(stage) + "\nACTION = " + repr(action) + "\n" + PROGRAM
    code, output, error = execute(client, "python3 - <<'OPERATIONS_UPDATE'\n" + program + "\nOPERATIONS_UPDATE\n",
                                  timeout=540 if action == "install" else 130)
    (FOLDER / ("operations-" + action + ".private.log")).write_text(output + "\n" + error, encoding="utf-8")
    report_path = VERIFY_REPORT if action == "verify" else REPORT
    with client.open_sftp() as sftp:
        sftp.get(stage + ("/verify-state.json" if action == "verify" else "/update-state.json"), str(report_path))
        for name in ("commands.private.log", action + "-error.private.log", "rollback-error.private.log"):
            try:
                sftp.stat(stage + "/" + name)
            except OSError:
                continue
            sftp.get(stage + "/" + name, str(FOLDER / ("operations-" + name)))
    result = json.loads(report_path.read_text(encoding="utf-8"))
    live.require(code == 0, "Operations " + action + " failed; inspect the private report")
    return result


def public_assets(expected):
    for name, resource in [("panel/web/index.html", ""), ("panel/web/app.js", "app.js"), ("panel/web/style.css", "style.css")]:
        status, headers, payload = live.request("GET", resource + "?v=" + expected[name][:16])
        live.require(status == 200 and hashlib.sha256(payload).hexdigest() == expected[name], "Public browser asset differs")
        cache = next((value for key, value in headers.items() if key.lower() == "cache-control"), "")
        live.require("no-store" in cache, "Public browser cache policy changed")


def deploy(manifest):
    sessions = login_sessions()
    sessions_file = FOLDER / "operations-sessions.private.json"
    sessions_file.write_text(json.dumps(sessions), encoding="utf-8")
    stage = PREFIX + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    client = None
    installed = False
    try:
        client = connect()
        code, _, _ = execute(client, "install -d -m 0700 " + shlex.quote(stage))
        live.require(code == 0, "Could not create the private operations stage")
        with client.open_sftp() as sftp:
            for local, remote in [(ARCHIVE, "release.tar.gz"), (MANIFEST, "manifest.json"), (sessions_file, "sessions.private.json")]:
                sftp.put(str(local), stage + "/" + remote)
                sftp.chmod(stage + "/" + remote, 0o600)
        result = remote_action(client, stage, "install")
        live.require(result.get("candidate_installed") and result.get("local_acceptance"), "Local operations acceptance failed")
        installed = True
        public_assets(manifest["source_sha256"])
        result = remote_action(client, stage, "finalize")
        live.require(result.get("success"), "Final operations acceptance failed")
        installed = False
        for name in FILES:
            destination = FOLDER / "panel-release" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(RELEASE / name), str(destination))
        print(json.dumps(result))
        return result
    except BaseException:
        if installed and client is not None:
            remote_action(client, stage, "rollback")
        raise
    finally:
        if client is not None:
            client.close()
        logout_sessions(sessions)
        if sessions_file.exists():
            sessions_file.unlink()


def verify_only():
    saved = json.loads(REPORT.read_text(encoding="utf-8"))
    live.require(saved.get("success"), "The saved operations deployment did not complete")
    manifest = frozen_manifest()
    client = connect()
    try:
        public_assets(manifest["source_sha256"])
        result = remote_action(client, saved["stage"], "verify")
        live.require(result.get("success"), "Operations verification failed")
        print(json.dumps(result))
    finally:
        client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.prepare_only:
        frozen = prepare()
        print(json.dumps({"prepared": True, "deployment_executed": False, "files": frozen["files"],
                          "archive_sha256": frozen["archive_sha256"], "python_syntax": "3.6"}))
    elif args.verify_only:
        verify_only()
    else:
        deploy(frozen_manifest())
