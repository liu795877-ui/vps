"""Freeze and publish the reviewed official per-account HY2 integration.

Preparation is local. Publishing checkpoints existing traffic, preserves all
REALITY/rule/account identities, installs private SOCKS bridges and replaces
the legacy HY2 trial with official isolated account instances. The root agent
owns deployment. A comparison journal prevents overwriting concurrent edits.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import importlib.util
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
from update_operations import public_assets


ROOT = FOLDER.parents[1]
FILES = ['panel/server.py', 'panel/accounts.py', 'panel/subscriptions.py',
         'panel/telemetry.py', 'panel/backups.py', 'panel/hy2.py', 'panel/accelerated_client.py',
         'panel/test_accounts.py', 'panel/test_operations.py', 'panel/test_hy2_integration.py',
         'panel/test_hy2_telemetry.py', 'panel/test_hy2_backups.py', 'panel/test_accelerated_client.py',
         'panel/web/style.css', 'panel/web/app.js', 'panel/web/index.html']
HELPERS = ['hy2-integration-remote.py', 'remote-integration-verification.py']
RELEASE = FOLDER / 'hy2-integration-release'
ARCHIVE = FOLDER / 'hy2-integration-release.tar.gz'
MANIFEST = FOLDER / 'hy2-integration-release-manifest.json'
REPORT = FOLDER / 'hy2-integration-update.json'
VERIFY_REPORT = FOLDER / 'hy2-integration-verification.json'
PREFIX = '/root/raksmart-proxy-deploy-20261009/hy2-integration-'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_file(path):
    return (path.is_file() and not path.is_symlink() and '__pycache__' not in path.parts
            and path.suffix != '.pyc' and '.private.' not in path.name)


def prepare():
    baseline = FOLDER / 'panel-release'
    live.require(baseline.is_dir() and not baseline.is_symlink(), 'Deployed compatible baseline is missing')
    names = sorted(path.relative_to(baseline).as_posix() for path in baseline.rglob('*') if source_file(path))
    live.require('configure_reality.py' in names and 'panel/telemetry.py' in names,
                 'Existing-node adoption and operations source are missing')
    if RELEASE.exists():
        live.require(RELEASE.resolve().parent == FOLDER.resolve() and not RELEASE.is_symlink()
                     and RELEASE.name == 'hy2-integration-release', 'Unsafe local freeze directory')
        shutil.rmtree(RELEASE)
    RELEASE.mkdir()
    for name in names:
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((baseline / name).read_bytes())
    for name in FILES:
        source = ROOT / name
        live.require(source_file(source), 'Requested integration source is missing: ' + name)
        text = source.read_text(encoding='utf-8')
        if name.endswith('.py'):
            text = compatible(text, name)
            ast.parse(text, filename=name, feature_version=(3, 6))
        destination = RELEASE / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding='utf-8')
    names = sorted(set(names) | set(FILES))
    for name in names:
        if name.endswith('.py'):
            ast.parse((RELEASE / name).read_text(encoding='utf-8'), filename=name, feature_version=(3, 6))
    live.require((RELEASE / 'configure_reality.py').read_bytes() == (baseline / 'configure_reality.py').read_bytes(),
                 'The production REALITY adapter changed')
    # Keep the existing adoption tests from the baseline. Their one-inbound
    # case remains valid without an enabled HY2 registry; new HY2 tests verify
    # one VLESS base plus the private SOCKS running inbound separately.
    subprocess.run(['node', '--check', str(RELEASE / 'panel/web/app.js')], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, creationflags=live.NO_WINDOW)
    for name in HELPERS:
        ast.parse((FOLDER / name).read_text(encoding='utf-8'), filename=name, feature_version=(3, 6))
    ast.parse(PROGRAM, filename='hy2_integration_remote_update.py', feature_version=(3, 6))
    with tarfile.open(ARCHIVE, 'w:gz') as bundle:
        for name in names:
            bundle.add(RELEASE / name, arcname='release/' + name, recursive=False)
        for name in HELPERS:
            bundle.add(FOLDER / name, arcname='helpers/' + name, recursive=False)
    baseline_hashes = {name: sha(baseline / name) for name in names if (baseline / name).is_file()}
    manifest = {'version': 1, 'deployment_ip': live.IP, 'files': FILES, 'release_files': names,
        'prepared_at': datetime.now(timezone.utc).isoformat(), 'archive_sha256': sha(ARCHIVE),
        'source_sha256': {name: sha(RELEASE / name) for name in FILES},
        'release_sha256': {name: sha(RELEASE / name) for name in names},
        'baseline_sha256': baseline_hashes, 'helper_sha256': {name: sha(FOLDER / name) for name in HELPERS},
        'remote_program_sha256': hashlib.sha256(PROGRAM.encode('utf-8')).hexdigest(),
        'python_syntax': '3.6', 'configure_reality_adapter_preserved': True,
        'official_hy2_version': 'v2.13.0',
        'official_hy2_sha256': '907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691',
        'certificate_sha256': '719524027ace548d1251736cb2a2f603572d380e2237f8bdf8d3a3913af2b597',
        'state_mutations': ['managed_hash', 'profile', 'profile_version', 'profile_hash', 'profile_updated'],
        'legacy_password_revoked': True, 'deployment_executed': False}
    MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def frozen_manifest():
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    live.require(manifest.get('version') == 1 and manifest.get('deployment_ip') == live.IP
                 and manifest.get('files') == FILES, 'Unexpected integration manifest')
    live.require(sha(ARCHIVE) == manifest['archive_sha256']
                 and hashlib.sha256(PROGRAM.encode('utf-8')).hexdigest() == manifest['remote_program_sha256'],
                 'Frozen archive or publisher changed')
    for name in manifest['release_files']:
        live.require(isinstance(name, str) and not Path(name).is_absolute() and '..' not in Path(name).parts,
                     'Unsafe source path')
        live.require(sha(RELEASE / name) == manifest['release_sha256'][name], 'Frozen source changed')
    for name in HELPERS:
        live.require(sha(FOLDER / name) == manifest['helper_sha256'][name], 'Frozen host helper changed')
    return manifest


PROGRAM = r'''
import copy, grp, hashlib, importlib.util, json, os, py_compile, re, shutil, socket, stat, subprocess, sys, tarfile, time, traceback
from pathlib import Path
from urllib.request import Request, urlopen

stage = Path(STAGE)
target = Path('/opt/vps-panel')
directory = Path('/var/lib/vps-panel')
registry = directory / 'users.private.json'
hy2_registry = directory / 'hy2.private.json'
hy2_dropin = Path('/etc/systemd/system/vps-panel.service.d/hy2-paths.conf')
manifest = json.loads((stage / 'manifest.json').read_text())
result = {'success': False, 'phase': 'preflight', 'deployment_ip': '198.200.49.63',
          'stage': str(stage), 'backup': str(stage / 'before'), 'identity_preserved': False,
          'proxy_restarts': [], 'legacy_password_revoked': False}

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')

def private_json(path, value):
    path.write_bytes(json_bytes(value))
    path.chmod(0o600)

def record(phase):
    result['phase'] = phase
    private_json(stage / 'update-state.json', result)

def run(args, timeout=30, cwd=None, env=None):
    response = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, cwd=cwd, env=env)
    with (stage / 'commands.private.log').open('ab') as stream:
        stream.write(response.stdout + b'\n' + response.stderr)
    require(response.returncode == 0, 'Host command failed during ' + result['phase'])
    return response

def attributes(path):
    info = path.stat()
    return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}

def service_snapshot(name):
    raw = run(['systemctl', 'show', name, '--property=ActiveState', '--property=UnitFileState',
               '--property=MainPID', '--property=ExecMainStartTimestampMonotonic']).stdout.decode()
    return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)

def inventory():
    data = json.loads(registry.read_text())
    require(data.get('version') == 1 and isinstance(data.get('users'), list) and len(data['users']) <= 2,
            'Invalid existing account registry')
    users = [{'id': 'admin', 'port': 443, 'enabled': True,
              'state': str(directory / 'state.private.json'), 'config': '/usr/local/etc/xray/config.json',
              'service': 'xray.service'}]
    identities, ports = set(), set()
    for account in data['users']:
        identity, port = account.get('id'), account.get('port')
        require(isinstance(identity, str) and re.fullmatch(r'[a-f0-9]{16}', identity)
                and identity not in identities and type(port) is int and port in (1443, 2443)
                and port not in ports and type(account.get('enabled')) is bool, 'Invalid member identity')
        identities.add(identity); ports.add(port)
        users.append({'id': identity, 'port': port, 'enabled': account['enabled'],
            'state': str(directory / 'users' / identity / 'state.private.json'),
            'config': '/usr/local/etc/xray-members/' + identity + '/config.json',
            'service': 'xray-panel@' + identity + '.service'})
    return users

def protected_paths():
    paths = [registry, directory / 'auth.private.json', directory / 'base.private.yaml',
             Path('/etc/caddy/Caddyfile'), Path('/etc/resolv.conf'),
             Path('/etc/systemd/system/xray.service'), Path('/etc/systemd/system/xray-panel@.service'),
             Path('/etc/systemd/system/vps-panel.service'), Path('/etc/systemd/system/raksmart-hy2.service'),
             Path('/usr/local/bin/raksmart-hysteria2'), Path('/usr/local/etc/raksmart-hy2/server.crt.pem'),
             Path('/usr/local/etc/raksmart-hy2/server.key.pem')]
    paths.extend(target / name for name in manifest['baseline_sha256'] if name not in manifest['files'])
    for name in ('vps-panel.service', 'xray.service', 'xray-panel@.service', 'caddy.service', 'raksmart-hy2.service'):
        dropins = Path('/etc/systemd/system') / (name + '.d')
        if dropins.is_dir():
            require(not dropins.is_symlink(), 'A protected drop-in directory is linked')
            paths.extend(path for path in dropins.glob('*.conf') if path != hy2_dropin)
    return sorted(set(paths))

def snapshot():
    users = inventory()
    protected = {}
    for path in protected_paths():
        require(path.is_file() and not path.is_symlink(), 'A protected source is unavailable')
        protected[str(path)] = {'sha256': sha(path), 'attributes': attributes(path)}
    configs, states, services = {}, {}, {}
    for user in users:
        config_path, state_path = Path(user['config']), Path(user['state'])
        require(all(path.is_file() and not path.is_symlink() for path in (config_path, state_path)),
                'Unsafe account files')
        state = json.loads(state_path.read_text())
        require(state.get('managed_hash') == sha(config_path)
                and len(state['base']['inbounds']) == 1
                and state['base']['inbounds'][0]['port'] == user['port'], 'Account state and running configuration differ')
        configs[user['id']] = {'sha256': sha(config_path), 'attributes': attributes(config_path)}
        states[user['id']] = {'sha256': sha(state_path), 'attributes': attributes(state_path)}
        services[user['service']] = service_snapshot(user['service'])
        require((services[user['service']]['ActiveState'] == 'active') == user['enabled'],
                'Member enablement differs from its service')
    ipv6 = run(['ip', '-6', 'addr', 'show', 'scope', 'global']).stdout.decode()
    for user in users:
        config = json.loads(Path(user['config']).read_text())
        # Avoid a v6 ingress bypass of the IPv4 quota/shaping implementation.
        require(not ipv6.strip() or config['inbounds'][0].get('listen') == '0.0.0.0',
                'Public IPv6 needs an explicitly reviewed ingress migration')
    return {'users': users, 'protected': protected, 'configs': configs, 'states': states,
            'services': services, 'caddy': service_snapshot('caddy.service')}

def wait_idle():
    sessions = json.loads((stage / 'sessions.private.json').read_text())
    require(set(sessions) == {user['id'] for user in inventory() if user['enabled']},
            'Enabled account preflight sessions are incomplete')
    deadline = time.monotonic() + 45
    while True:
        idle = True
        for identity, item in sessions.items():
            request = Request('http://127.0.0.1:18787/api/state', headers={'Cookie': item['cookie']})
            with urlopen(request, timeout=4) as response:
                data = json.loads(response.read().decode())
            require(data.get('user', {}).get('id') == identity, 'Preflight session belongs to another account')
            idle = idle and (data.get('job') or {}).get('status') != 'running'
        if idle:
            return
        require(time.monotonic() < deadline, 'An account operation is still running')
        time.sleep(.25)

def safe_extract():
    require(sha(stage / 'release.tar.gz') == manifest['archive_sha256'], 'Release archive checksum differs')
    expected = {'release/' + name for name in manifest['release_files']} | {
        'helpers/' + name for name in manifest['helper_sha256']}
    with tarfile.open(str(stage / 'release.tar.gz'), 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len(expected) and {item.name for item in members} == expected
                and all(item.isfile() for item in members) and sum(item.size for item in members) < 30000000,
                'Unreviewed archive content')
        for item in members:
            require(not item.name.startswith('/') and '..' not in Path(item.name).parts
                    and '\\' not in item.name, 'Unsafe archive path')
            destination = stage / item.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(item) as source, destination.open('xb') as output:
                output.write(source.read())
            destination.chmod(0o600)
    for name in manifest['release_files']:
        source = stage / 'release' / name
        require(sha(source) == manifest['release_sha256'][name], 'Frozen candidate source differs')
        if name in manifest['baseline_sha256']:
            require((target / name).is_file() and sha(target / name) == manifest['baseline_sha256'][name],
                    'Deployed baseline source changed concurrently')
        else:
            require(not (target / name).exists(), 'Proposed new source already exists')
        if name.endswith('.py'):
            py_compile.compile(str(source), doraise=True)
    for name, digest in manifest['helper_sha256'].items():
        require(sha(stage / 'helpers' / name) == digest, 'Host helper checksum differs')
        py_compile.compile(str(stage / 'helpers' / name), doraise=True)

def atomic(path, data, info):
    require(not path.is_symlink(), 'Refusing to replace a linked destination')
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name('.' + path.name + '.hy2-integration-' + stage.name[-6:])
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(), info['mode']); os.fchown(stream.fileno(), info['uid'], info['gid'])
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()

def checkpoint():
    program = ("from panel import server\nfrom panel.accounts import Accounts\nfrom panel.telemetry import Telemetry\n"
        "m=server.Manager('/var/lib/vps-panel','198.200.49.63',origin='" + ORIGIN + "',base_path='/node-console/')\n"
        "a=Accounts(m,'/var/lib/vps-panel/auth.private.json')\nt=Telemetry(a)\nt.tick()\n")
    environment = os.environ.copy(); environment['PYTHONPATH'] = str(target) + ':' + str(target / 'vendor')
    run([sys.executable, '-c', program], cwd=str(target), env=environment)
    result['traffic_checkpointed'] = True

def migration(before):
    sys.path.insert(0, str(stage / 'release'))
    from panel import server, hy2, subscriptions
    # Candidate builders use supplied state only; avoid Manager initialization
    # side effects and do not apply unsaved exit/rule drafts.
    data = {'version': 1, 'enabled': True, 'certificate_sha256': manifest['certificate_sha256'],
            'sni': 'raksmart-hy2.local', 'accounts': {user['id']: hy2._entry(user['port']) for user in before['users']}}
    hy2.validate_registry(data)
    integration = object.__new__(hy2.Integration)
    integration.data = data
    owner = type('Owner', (), {'directory': directory})()
    integration.accounts = type('AccountContext', (), {'owner_manager': owner})()
    mutations = [(hy2_registry, json_bytes(data), {'mode': 0o600, 'uid': 0, 'gid': 0})]
    instance_stage = stage / 'instances'; instance_stage.mkdir(mode=0o700)
    instance_manifest = {'version': 1, 'binary_sha256': manifest['official_hy2_sha256'],
                         'certificate_sha256': manifest['certificate_sha256'], 'instances': []}
    for user in before['users']:
        state_path, config_path = Path(user['state']), Path(user['config'])
        old_state, old_config = json.loads(state_path.read_text()), json.loads(config_path.read_text())
        applied = copy.deepcopy(old_state)
        applied.update(exits=copy.deepcopy(old_state['applied_exits']),
            domains=list(old_state.get('applied_domains', [])),
            direct_domains=list(old_state.get('applied_direct_domains', [])),
            routing_mode=old_state.get('applied_routing_mode', 'manual'))
        manager = object.__new__(server.Manager)
        manager.public_ip = '198.200.49.63'; manager.origin = ORIGIN; manager.base_path = '/node-console/'
        manager.acceleration = integration
        candidate, profile = manager.build(applied, old_state['active_id'])
        old_providers = set(re.findall(r'^\s*url:\s*(.+?)\s*$', old_state.get('profile', ''), re.M))
        new_providers = set(re.findall(r'^\s*url:\s*(.+?)\s*$', profile, re.M))
        require(new_providers == old_providers, 'Migration changed existing rule-provider URLs')
        def provider_section(value):
            match = re.search(r'^rule-providers:[^\n]*\n', value, re.M)
            if not match:
                return None
            following = re.search(r'^[A-Za-z][A-Za-z0-9_-]*:', value[match.end():], re.M)
            end = match.end() + following.start() if following else len(value)
            return value[match.start():end]
        require(provider_section(profile) == provider_section(old_state.get('profile', '')),
                'Migration changed rule-provider content or inline capability URLs')
        integration.validate_running(user, candidate)
        primary = candidate['inbounds'][0]
        require(primary == old_config['inbounds'][0], 'Migration changed a VLESS identity or REALITY setting')
        require(candidate['outbounds'] == old_config['outbounds'], 'Migration changed an applied exit')
        unchanged_rules = [rule for rule in candidate['routing']['rules']
                           if rule.get('inboundTag') != ['panel-hy2-socks']]
        require(unchanged_rules == old_config['routing']['rules'], 'Migration changed existing routing rules')
        payload = json_bytes(candidate)
        new_state = copy.deepcopy(old_state)
        new_state.update(managed_hash=hashlib.sha256(payload).hexdigest(), profile=profile)
        subscriptions.update_metadata(new_state, old_state)
        allowed = set(manifest['state_mutations'])
        require({key: value for key, value in new_state.items() if key not in allowed}
                == {key: value for key, value in old_state.items() if key not in allowed},
                'Migration replaced account settings, credentials, rules, drafts or history')
        require(new_state.get('profile_token') == old_state.get('profile_token'), 'Subscription capability rotated')
        test_path = stage / ('candidate-' + user['id'] + '.private.json')
        test_path.write_bytes(payload); test_path.chmod(0o600)
        run(['/usr/local/bin/xray', 'run', '-test', '-config', str(test_path)])
        mutations.extend([(config_path, payload, before['configs'][user['id']]['attributes']),
                          (state_path, json_bytes(new_state), before['states'][user['id']]['attributes'])])
        instance_config = json_bytes(integration.config(user))
        filename = '{}.yaml'.format(user['port'])
        (instance_stage / filename).write_bytes(instance_config); (instance_stage / filename).chmod(0o600)
        instance_manifest['instances'].append({'port': user['port'], 'enabled': user['enabled'],
            'config': filename, 'sha256': hashlib.sha256(instance_config).hexdigest()})
    private_json(instance_stage / 'manifest.json', instance_manifest)
    for name in manifest['files']:
        path = target / name
        mutations.append((path, (stage / 'release' / name).read_bytes(),
                          attributes(path) if path.exists() else {'mode': 0o644, 'uid': 0, 'gid': 0}))
    require(not hy2_dropin.exists() and not hy2_dropin.is_symlink(), 'An independent HY2 write-path drop-in exists')
    mutations.append((hy2_dropin, b'[Service]\nReadWriteDirectories=/usr/local/etc/raksmart-hy2/accounts\n',
                      {'mode': 0o644, 'uid': 0, 'gid': 0}))
    return mutations

def journal_entry(path, data, info):
    require(not path.is_symlink(), 'Transactional destination is linked')
    exists = path.exists()
    relative = str(path).lstrip('/')
    if exists:
        require(path.is_file(), 'Transactional destination is not a regular file')
        destination = stage / 'before/files' / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(path.read_bytes()); destination.chmod(0o600)
    return {'path': str(path), 'backup': relative, 'existed': exists,
            'before_sha256': sha(path) if exists else None,
            'after_sha256': hashlib.sha256(data).hexdigest(), 'attributes': info}

def wait_proxy(user):
    for unused in range(40):
        try:
            run(['systemctl', 'is-active', '--quiet', user['service']])
            with socket.create_connection(('127.0.0.1', user['port']), timeout=.4):
                return
        except Exception:
            time.sleep(.25)
    raise RuntimeError('Account VLESS service did not become ready')

def start_panel():
    run(['systemctl', 'start', 'vps-panel.service'])
    for unused in range(40):
        try:
            with urlopen('http://127.0.0.1:18787/api/session', timeout=1) as response:
                if response.status == 200:
                    return
        except Exception:
            time.sleep(.25)
    raise RuntimeError('Panel did not become ready')

def host_verify(before):
    command = [sys.executable, str(stage / 'helpers/remote-integration-verification.py'), 'host',
               '--active-ports', ','.join(str(user['port']) for user in before['users'] if user['enabled'])]
    verification = json.loads(run(command).stdout.decode())
    require(verification.get('host_verified') and verification.get('legacy_revoked'), 'HY2 host acceptance failed')
    return verification

def installed_verified(before, transaction):
    after = snapshot()
    require(after['users'] == before['users'] and after['protected'] == before['protected']
            and after['caddy'] == before['caddy'], 'Protected identity/source/service changed')
    for user in before['users']:
        for field in ('ActiveState', 'UnitFileState'):
            require(after['services'][user['service']][field] == before['services'][user['service']][field],
                    'Account service enablement changed')
        if not user['enabled']:
            require(after['services'][user['service']] == before['services'][user['service']],
                    'A disabled member service was restarted')
    for entry in transaction['installed']:
        require(Path(entry['path']).is_file() and sha(entry['path']) == entry['after_sha256'],
                'Installed transaction bytes changed concurrently')
    for name, resource in (('panel/web/index.html', '/'), ('panel/web/app.js', '/app.js'), ('panel/web/style.css', '/style.css')):
        with urlopen('http://127.0.0.1:18787' + resource, timeout=3) as response:
            require(hashlib.sha256(response.read()).hexdigest() == manifest['source_sha256'][name],
                    'Served browser source differs')
    return host_verify(before)

def rollback():
    before = json.loads((stage / 'before/snapshot.private.json').read_text())
    transaction = json.loads((stage / 'transaction.private.json').read_text())
    run(['systemctl', 'stop', 'vps-panel.service'])
    entries = []
    for entry in transaction['installed']:
        path = Path(entry['path'])
        require(not path.is_symlink(), 'A linked destination prevents rollback')
        if not path.exists() and not entry['existed']:
            continue
        require(path.is_file(), 'A transactional destination disappeared')
        current = sha(path)
        if entry['existed'] and current == entry['before_sha256']:
            continue
        require(current == entry['after_sha256'], 'A concurrent edit prevents automatic rollback')
        entries.append(entry)
    if transaction.get('hy2_install_started') and Path(transaction['hy2_snapshot']).is_dir():
        run([sys.executable, str(stage / 'helpers/hy2-integration-remote.py'), 'rollback',
             '--snapshot', transaction['hy2_snapshot']], timeout=60)
    for entry in reversed(entries):
        path = Path(entry['path'])
        if entry['existed']:
            atomic(path, (stage / 'before/files' / entry['backup']).read_bytes(), entry['attributes'])
        else:
            path.unlink()
    for user in before['users']:
        if user['service'] in transaction['restarted']:
            run(['systemctl', 'restart', user['service']]); wait_proxy(user)
    run(['systemctl', 'daemon-reload'])
    start_panel()
    after = snapshot()
    require(after['configs'] == before['configs'] and after['states'] == before['states']
            and after['protected'] == before['protected'], 'Original account/source bytes did not recover')
    result.update(success=False, phase='rolled-back', source_rollback_succeeded=True,
                  configuration_rollback_succeeded=True, identity_preserved=True)
    private_json(stage / 'update-state.json', result)

try:
    os.umask(0o077)
    require(manifest.get('version') == 1 and manifest.get('deployment_ip') == '198.200.49.63',
            'Unexpected frozen target')
    if ACTION == 'install':
        record('preflight')
        require(not hy2_registry.exists(), 'HY2 account registry already exists; use a reviewed subsequent upgrade')
        run(['systemctl', 'is-active', '--quiet', 'vps-panel.service'])
        safe_extract()
        initial = snapshot()
        record('candidate-tests')
        environment = os.environ.copy()
        environment['PYTHONPATH'] = str(target / 'vendor'); environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
        run([sys.executable, '-m', 'unittest', 'test_configure_reality', 'test_configure_static_exits',
             'panel.test_panel', 'panel.test_routing', 'panel.test_accounts', 'panel.test_multiuser_http',
             'panel.test_subscriptions', 'panel.test_operations', 'panel.test_enhancements_http',
             'panel.test_accelerated_client', 'panel.test_hy2_integration', 'panel.test_hy2_telemetry',
             'panel.test_hy2_backups'], timeout=300, cwd=str(stage / 'release'), env=environment)
        require(snapshot() == initial, 'An account changed during candidate tests')
        wait_idle(); record('stop-panel'); run(['systemctl', 'stop', 'vps-panel.service'])
        require(snapshot() == initial, 'An account operation raced the panel stop')
        record('checkpoint-traffic'); checkpoint()
        before = snapshot()
        (stage / 'before').mkdir(mode=0o700)
        private_json(stage / 'before/snapshot.private.json', before)
        transaction = {'installed': [], 'restarted': [], 'hy2_install_started': False,
            'hy2_snapshot': '/root/hy2-integration-backup-' + stage.name.split('hy2-integration-', 1)[1]}
        private_json(stage / 'transaction.private.json', transaction)
        record('validate-account-migration')
        mutations = migration(before)
        journal = [journal_entry(path, data, info) for path, data, info in mutations]
        private_json(stage / 'planned-mutations.private.json', journal)
        record('install-reviewed-transaction')
        for (path, data, info), entry in zip(mutations, journal):
            require((sha(path) == entry['before_sha256']) if entry['existed'] else not path.exists(),
                    'A destination changed concurrently')
            transaction['installed'].append(entry); private_json(stage / 'transaction.private.json', transaction)
            atomic(path, data, info)
        record('restart-account-socks-bridges')
        for user in before['users']:
            if user['enabled']:
                transaction['restarted'].append(user['service']); private_json(stage / 'transaction.private.json', transaction)
                run(['systemctl', 'restart', user['service']]); wait_proxy(user)
                result['proxy_restarts'].append(user['service'])
        record('replace-legacy-hy2')
        transaction['hy2_install_started'] = True; private_json(stage / 'transaction.private.json', transaction)
        installation = json.loads(run([sys.executable, str(stage / 'helpers/hy2-integration-remote.py'),
            'install', '--stage', str(stage / 'instances'), '--snapshot', transaction['hy2_snapshot']], timeout=90).stdout.decode())
        require(installation.get('installed') and installation.get('legacy_revoked'), 'Official HY2 installation failed')
        run(['systemctl', 'daemon-reload'])
        record('start-panel'); start_panel()
        result['host_verification'] = installed_verified(before, transaction)
        result.update(candidate_installed=True, local_acceptance=True, identity_preserved=True,
            legacy_password_revoked=True, disabled_members_preserved=True, phase='pending-public-acceptance')
        private_json(stage / 'update-state.json', result)
    elif ACTION in ('verify', 'finalize'):
        result = json.loads((stage / 'update-state.json').read_text())
        before = json.loads((stage / 'before/snapshot.private.json').read_text())
        transaction = json.loads((stage / 'transaction.private.json').read_text())
        result['host_verification'] = installed_verified(before, transaction)
        result.update(success=True, phase='complete' if ACTION == 'finalize' else 'verified')
        private_json(stage / ('verify-state.json' if ACTION == 'verify' else 'update-state.json'), result)
    elif ACTION == 'rollback':
        result = json.loads((stage / 'update-state.json').read_text()); rollback()
    else:
        raise RuntimeError('Unsupported integration action')
except BaseException:
    (stage / (ACTION + '-error.private.log')).write_text(traceback.format_exc())
    if ACTION == 'install' and (stage / 'transaction.private.json').is_file():
        try:
            rollback()
        except BaseException:
            (stage / 'rollback-error.private.log').write_text(traceback.format_exc())
            result['rollback_failed'] = True
    elif ACTION == 'install' and result.get('phase') in ('stop-panel', 'checkpoint-traffic'):
        try:
            start_panel()
        except BaseException:
            result['panel_recovery_failed'] = True
    result.update(success=False, phase='failed')
    private_json(stage / ('verify-state.json' if ACTION == 'verify' else 'update-state.json'), result)
    print(json.dumps(result)); sys.exit(1)
print(json.dumps(result))
'''


def remote_action(client, stage, action):
    live.require(action in ('install', 'verify', 'finalize', 'rollback'), 'Unsupported remote action')
    live.require(re.fullmatch(re.escape(PREFIX) + r'[0-9]{8}T[0-9]{6}-[a-f0-9]{6}', stage), 'Unsafe remote stage')
    program = 'STAGE = ' + repr(stage) + '\nACTION = ' + repr(action) + '\nORIGIN = ' + repr(live.ORIGIN) + '\n' + PROGRAM
    code, output, error = execute(client, "python3 - <<'HY2_INTEGRATION_UPDATE'\n" + program + '\nHY2_INTEGRATION_UPDATE\n',
                                  timeout=540 if action == 'install' else 150)
    (FOLDER / ('hy2-integration-' + action + '.private.log')).write_text(output + '\n' + error, encoding='utf-8')
    destination = VERIFY_REPORT if action == 'verify' else REPORT
    with client.open_sftp() as sftp:
        sftp.get(stage + ('/verify-state.json' if action == 'verify' else '/update-state.json'), str(destination))
        for filename in ('commands.private.log', action + '-error.private.log', 'rollback-error.private.log'):
            try:
                sftp.stat(stage + '/' + filename)
            except OSError:
                continue
            sftp.get(stage + '/' + filename, str(FOLDER / ('hy2-integration-' + filename)))
    result = json.loads(destination.read_text(encoding='utf-8'))
    live.require(code == 0, 'HY2 integration action failed; inspect its private deployment logs')
    return result


def deploy(manifest):
    sessions = login_sessions()
    session_file = FOLDER / 'hy2-integration-sessions.private.json'
    session_file.write_text(json.dumps(sessions), encoding='utf-8')
    stage = PREFIX + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + secrets.token_hex(3)
    client, installed = None, False
    try:
        client = connect()
        code, unused, unused_error = execute(client, 'install -d -m 0700 ' + shlex.quote(stage))
        live.require(code == 0, 'Private deployment directory creation failed')
        with client.open_sftp() as sftp:
            for local, name in ((ARCHIVE, 'release.tar.gz'), (MANIFEST, 'manifest.json'), (session_file, 'sessions.private.json')):
                sftp.put(str(local), stage + '/' + name); sftp.chmod(stage + '/' + name, 0o600)
        result = remote_action(client, stage, 'install')
        live.require(result.get('candidate_installed') and result.get('local_acceptance'), 'Local HY2 acceptance failed')
        installed = True
        public_assets(manifest['source_sha256'])
        spec = importlib.util.spec_from_file_location('hy2_public_privacy', FOLDER / 'remote-integration-verification.py')
        verification = importlib.util.module_from_spec(spec); spec.loader.exec_module(verification)
        privacy = verification.privacy()
        live.require(privacy.get('privacy_verified'), 'A private HY2 statistics or SOCKS port is publicly reachable')
        result = remote_action(client, stage, 'finalize')
        live.require(result.get('success'), 'Final HY2 acceptance failed')
        installed = False
        for name in FILES:
            destination = FOLDER / 'panel-release' / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(RELEASE / name, destination)
        print(json.dumps(result)); return result
    except BaseException:
        if installed and client is not None:
            remote_action(client, stage, 'rollback')
        raise
    finally:
        if client is not None:
            client.close()
        logout_sessions(sessions)
        if session_file.exists():
            session_file.unlink()


def verify_only():
    saved = json.loads(REPORT.read_text(encoding='utf-8'))
    live.require(saved.get('success'), 'No completed HY2 integration deployment is recorded')
    manifest = frozen_manifest(); client = connect()
    try:
        public_assets(manifest['source_sha256'])
        result = remote_action(client, saved['stage'], 'verify')
        print(json.dumps(result))
    finally:
        client.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare-only', action='store_true')
    group.add_argument('--deploy', action='store_true')
    group.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    if args.prepare_only:
        frozen = prepare()
        print(json.dumps({'prepared': True, 'deployment_executed': False,
                          'archive_sha256': frozen['archive_sha256'], 'python_syntax': '3.6'}))
    elif args.verify_only:
        verify_only()
    else:
        deploy(frozen_manifest())
