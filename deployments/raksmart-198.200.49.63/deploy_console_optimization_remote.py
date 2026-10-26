"""Python 3.6 transaction for one frozen .63 source-only console update.

Only main() runs actions. Configuration and login credentials arrive on stdin;
credentials are never written. Private checkpoints retain code originals and
protected-file hashes; state, traffic, certificates and units are never restored.
"""
import argparse
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import time

APP = Path('/opt/vps-panel')
DATA = Path('/var/lib/vps-panel')
PANEL = 'vps-panel.service'
LOCK = Path('/run/lock/vps-console-source-deploy.lock')
FORMAT = 'vps-console-source-transaction-v1'
SOURCE_FORMAT = 'vps-console-optimization-release-v1'
SUPPORTED = (443, 1443, 2443, 3444, 4444, 5444, 6445, 7445)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_data(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def safe(path, regular=False, missing=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Absolute canonical host path required')
    for part in [path] + list(path.parents):
        require(not part.is_symlink(), 'Symbolic host path rejected: ' + str(part))
    require(missing or path.exists(), 'Host path missing: ' + str(path))
    if path.exists() and regular:
        require(path.is_file() and stat.S_ISREG(path.stat().st_mode), 'Host file is not regular: ' + str(path))
    return path


def attributes(path):
    item = safe(path, regular=True).stat()
    return {'mode': stat.S_IMODE(item.st_mode), 'uid': item.st_uid, 'gid': item.st_gid,
            'atime_ns': item.st_atime_ns, 'mtime_ns': item.st_mtime_ns}


def atomic(path, payload, info=None):
    path = safe(path, regular=True, missing=True)
    safe(path.parent)
    temporary = path.with_name('.' + path.name + '.console-deploy-' + secrets.token_hex(8))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            if info:
                os.fchown(stream.fileno(), info['uid'], info['gid'])
                os.fchmod(stream.fileno(), info['mode'])
        if info:
            os.utime(str(temporary), ns=(info['atime_ns'], info['mtime_ns']))
        os.replace(str(temporary), str(path))
        directory_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json(path, value):
    atomic(path, json_data(value))


def run(args, check=True, timeout=20):
    environment = os.environ.copy()
    environment['LC_ALL'] = 'C'
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=environment)
    require(not check or result.returncode == 0, 'Host command failed: ' + args[0])
    return result


def service(name):
    result = run(['systemctl', 'show', name, '--property=ActiveState', '--property=SubState',
                  '--property=UnitFileState', '--property=MainPID',
                  '--property=LoadState', '--property=FragmentPath',
                  '--property=ActiveEnterTimestampMonotonic', '--property=ExecMainStartTimestampMonotonic'])
    values = dict(line.split('=', 1) for line in result.stdout.decode('utf-8').splitlines() if '=' in line)
    require({'ActiveState', 'SubState', 'UnitFileState', 'MainPID',
             'ExecMainStartTimestampMonotonic'} <= set(values), 'Incomplete service observation')
    return values


def records():
    registry = json.loads(safe(DATA / 'users.private.json', True).read_text(encoding='utf-8'))
    require(registry.get('version') == 1 and isinstance(registry.get('users'), list), 'Invalid account registry')
    result = [{'id': 'admin', 'username': 'admin', 'port': 443, 'enabled': True}]
    names, ids, ports = set(), set(), set()
    for item in registry['users']:
        identity, port = item.get('id'), item.get('port')
        require(isinstance(identity, str) and re.fullmatch(r'[a-f0-9]{16}', identity)
                and identity not in ids and type(port) is int and port in SUPPORTED[1:]
                and port not in ports and type(item.get('enabled')) is bool
                and isinstance(item.get('username'), str) and item['username'] not in names,
                'Invalid member identity or port')
        result.append({key: item[key] for key in ('id', 'username', 'port', 'enabled')})
        ids.add(identity)
        names.add(item['username'])
        ports.add(port)
    require(len(result) <= len(SUPPORTED), 'Too many adopted members')
    auth = json.loads(safe(DATA / 'auth.private.json', True).read_text(encoding='utf-8'))
    result[0]['username'] = auth['username']
    return result


def launch_context():
    status = service(PANEL)
    require(status['ActiveState'] == 'active' and int(status['MainPID']) > 0, 'Panel must be running')
    argv = safe(Path('/proc') / status['MainPID'] / 'cmdline', True).read_bytes().decode('utf-8').split('\0')
    require(str(APP / 'panel/server.py') in argv, 'Running panel package differs')
    def argument(name, default):
        require(argv.count(name) <= 1, 'Repeated launch option')
        return argv[argv.index(name) + 1] if name in argv else default
    require(argument('--directory', str(DATA)) == str(DATA)
            and argument('--config', '/usr/local/etc/xray/config.json') == '/usr/local/etc/xray/config.json'
            and argument('--public-ip', None) == '198.200.49.63'
            and argument('--port', '18787') == '18787'
            and argument('--base-path', '/node-console/') == '/node-console/', 'Unexpected panel launch paths')
    return {'origin': argument('--origin', None), 'panel': status}


def api(path, origin, data=None, session=None):
    headers = {'Origin': origin}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    if session:
        headers.update({'Cookie': session['cookie'], 'X-CSRF-Token': session['csrf']})
    connection = http.client.HTTPConnection('127.0.0.1', 18787, timeout=8)
    try:
        connection.request('GET' if data is None else 'POST', path,
                           None if data is None else json.dumps(data), headers)
        response = connection.getresponse()
        payload = response.read(2 * 1024 * 1024)
        return response.status, dict(response.getheaders()), json.loads(payload.decode('utf-8'))
    finally:
        connection.close()


def registry_preflight(item):
    """Inspect a member whose password exists only with its owner.

    The transaction rechecks a complete protected snapshot after stopping the
    worker and before replacing code. A job/configuration change aborts release;
    no account credential is reset to obtain a session for maintenance.
    """
    require(item['id'] != 'admin', 'Owner session is required for maintenance')
    state_path = DATA / 'users' / item['id'] / 'state.private.json'
    config_path = Path('/usr/local/etc/xray-members') / item['id'] / 'config.json'
    state = json.loads(safe(state_path, True).read_text(encoding='utf-8'))
    require(state.get('managed_hash') == sha(safe(config_path, True).read_bytes()),
            'Member state/config binding differs before maintenance')
    health_path = safe(DATA / 'health.private.json', True, missing=True)
    health = json.loads(health_path.read_text(encoding='utf-8')) if health_path.exists() else {}
    require(health.get(item['id'], {}).get('mode', 'manual') == 'manual',
            'Auto failover requires a quiet maintenance window')


def quiescent(context, credentials, allow_registry_preflight=False):
    observed = []
    for item in records():
        if not item['enabled']:
            continue
        credential = next((value for value in credentials if value.get('username') == item['username']), None)
        if credential is None and allow_registry_preflight:
            registry_preflight(item)
            observed.append(item['id'])
            continue
        require(credential is not None, 'No local login available to inspect one enabled account')
        status, headers, body = api('/api/login', context['origin'],
                                    {'username': credential['username'], 'password': credential['password']})
        require(status == 200, 'Account job preflight login failed')
        session = {'cookie': headers['Set-Cookie'].split(';', 1)[0], 'csrf': body['csrf']}
        try:
            status, unused, state = api('/api/state', context['origin'], session=session)
            require(status == 200 and state.get('user', {}).get('id') == item['id'], 'Account job preflight failed')
            require(not state.get('job') or state['job'].get('status') != 'running', 'An account job is running')
            require(not state.get('health', {}).get('checking'), 'A background health job is running')
            # Auto failover can intentionally restart a proxy immediately after
            # the panel restarts. Refuse that concurrent policy during deploy.
            require(state.get('health', {}).get('mode', 'manual') == 'manual', 'Auto failover requires a quiet maintenance window')
            if item['id'] == 'admin':
                status, unused, tasks = api('/api/users/provision', context['origin'], session=session)
                if status == 200:
                    require(not any(task.get('status') in ('queued', 'running') for task in tasks.get('tasks', [])),
                            'A member preparation task is running')
                else:
                    require(status == 404 and not (APP / 'panel/provisioning.py').exists(),
                            'Member task preflight unavailable')
            observed.append(item['id'])
        finally:
            api('/api/logout', context['origin'], {}, session)
    return len(observed)


def file_observation(path):
    path = safe(path, regular=True, missing=True)
    if not path.exists():
        return {'exists': False}
    info = attributes(path)
    return {'exists': True, 'sha256': sha(path.read_bytes()),
            'mode': info['mode'], 'uid': info['uid'], 'gid': info['gid']}


def tree_files(root):
    root = safe(root, missing=True)
    if not root.exists():
        return []
    require(root.is_dir(), 'Protected directory is not a directory')
    result = []
    for path in root.rglob('*'):
        safe(path)
        if path.is_file():
            result.append(path)
    return result


def firewall():
    result = {}
    for arguments in (['iptables-save'], ['ip6tables-save'], ['nft', 'list', 'ruleset'],
                      ['firewall-cmd', '--state']):
        executable = shutil.which(arguments[0])
        if executable:
            response = run(arguments, check=False)
            # iptables-save timestamps are comments, not rule state.
            output = b'\n'.join(line for line in response.stdout.splitlines() if not line.startswith(b'#'))
            if arguments[0] in ('iptables-save', 'ip6tables-save'):
                output = re.sub(br'\[[0-9]+:[0-9]+\]', b'[counter]', output)
            if arguments[0] == 'nft':
                output = re.sub(br'counter packets [0-9]+ bytes [0-9]+', b'counter packets COUNTER bytes COUNTER', output)
            result[arguments[0]] = {'returncode': response.returncode, 'sha256': sha(output)}
    require('iptables-save' in result, 'Firewall observation unavailable')
    return result


def network_policy():
    values = {}
    for key in ('net.ipv4.tcp_congestion_control', 'net.core.default_qdisc', 'net.core.rmem_max', 'net.core.wmem_max'):
        values[key] = run(['sysctl', '-n', key]).stdout.decode('utf-8').strip()
    traffic = {}
    for kind in ('qdisc', 'class'):
        traffic[kind] = sha(run(['tc', kind, 'show']).stdout)
    for interface in sorted(os.listdir('/sys/class/net')):
        require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', interface), 'Unexpected interface name')
        traffic[interface + ':filters'] = sha(run(['tc', 'filter', 'show', 'dev', interface]).stdout)
    return {'sysctl': values, 'traffic_control': traffic}


def sysctl_alias_observation(path):
    require(path == Path('/etc/sysctl.d/99-sysctl.conf') and path.is_symlink()
            and os.readlink(str(path)) == '../sysctl.conf', 'Unrecognized sysctl alias')
    target = safe('/etc/sysctl.conf', True)
    info = path.lstat()
    require(stat.S_ISLNK(info.st_mode), 'Sysctl alias type changed')
    return {'target': '../sysctl.conf', 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'target_sha256': sha(target.read_bytes())}


def unit_files(names):
    result = {}
    bases = ('/etc/systemd/system', '/usr/lib/systemd/system')
    for base in bases:
        for name in names:
            path = Path(base) / name
            if path.exists():
                result[str(path)] = file_observation(path)
            for item in tree_files(Path(base) / (name + '.d')):
                result[str(item)] = file_observation(item)
    # Enablement links are captured as link targets; never followed or written.
    root = safe('/etc/systemd/system')
    for directory in root.glob('*.wants'):
        safe(directory)
        for path in directory.iterdir():
            if path.name in names:
                result[str(path)] = ({'link': os.readlink(str(path))} if path.is_symlink()
                                     else file_observation(path))
    for name in ('xray-panel@.service', 'raksmart-hy2@.service'):
        fragments = {str(Path(base) / name) for base in bases if str(Path(base) / name) in result}
        require(fragments, 'Required proxy template is missing')
        prefix = name.split('@', 1)[0] + '@'
        instances = sorted(value for value in names if value.startswith(prefix) and value != name)
        require(instances, 'No known instance can verify the proxy template')
        # systemd 219 rejects a template show without an instance. Check the
        # active HY2 owner and one actual registered Xray member instead.
        instance = 'raksmart-hy2@443.service' if name == 'raksmart-hy2@.service' else instances[0]
        require(instance in instances, 'Known template instance is unavailable')
        observed = service(instance)
        require(observed.get('LoadState') == 'loaded' and observed.get('FragmentPath') in fragments,
                'Known proxy instance does not load the protected template')
        result['loaded:' + name] = {'instance': instance, 'LoadState': observed['LoadState'],
                                   'FragmentPath': observed['FragmentPath']}
    return result


def snapshot():
    account_records = records()
    paths = set(DATA / name for name in (
        'auth.private.json', 'users.private.json', 'state.private.json', 'base.private.yaml',
        'hy2.private.json', 'hy2-server.crt.pem', 'hy2-server.key.pem', 'subscriptions.private.json',
        'operations.private.json', 'backup-key.private.bin', 'entrance-pool.private.json',
        'member-tasks.private.json', 'traffic-controls.private.json'))
    paths.add(Path('/usr/local/etc/xray/config.json'))
    paths.add(APP / 'install-marker.json')
    profiles = {}
    service_names = {PANEL, 'caddy.service', 'raksmart-hy2.service', 'xray.service'}
    for item in account_records:
        state_path = DATA / 'state.private.json' if item['id'] == 'admin' else DATA / 'users' / item['id'] / 'state.private.json'
        config_path = Path('/usr/local/etc/xray/config.json') if item['id'] == 'admin' else Path('/usr/local/etc/xray-members') / item['id'] / 'config.json'
        state = json.loads(safe(state_path, True).read_text(encoding='utf-8'))
        require(state.get('managed_hash') == sha(safe(config_path, True).read_bytes()), 'State/config binding differs')
        profiles[item['id']] = sha(str(state.get('profile', '')).encode('utf-8'))
        paths.update((state_path, config_path))
        service_names.add('xray.service' if item['id'] == 'admin' else 'xray-panel@' + item['id'] + '.service')
    for path in tree_files(DATA / 'users') + tree_files('/usr/local/etc/xray-members'):
        paths.add(path)
    for path in tree_files('/usr/local/etc/raksmart-hy2') + tree_files('/etc/caddy') + tree_files(APP / 'vendor'):
        paths.add(path)
    paths.add(Path('/etc/sysctl.conf'))
    sysctl_aliases = {}
    for path in safe('/etc/sysctl.d').glob('*.conf'):
        if path.is_symlink():
            sysctl_aliases[str(path)] = sysctl_alias_observation(path)
        else:
            paths.add(safe(path, True))
    paths.update((Path('/etc/resolv.conf'), Path('/usr/local/bin/xray'), Path('/usr/local/bin/raksmart-hysteria2')))
    for port in SUPPORTED:
        service_names.add('raksmart-hy2@' + str(port) + '.service')
    units = service_names | {'xray-panel@.service', 'raksmart-hy2@.service'}
    health_path = safe(DATA / 'health.private.json', True, missing=True)
    health = json.loads(health_path.read_text(encoding='utf-8')) if health_path.exists() else {}
    settings = {identity: {key: value[key] for key in ('mode', 'fallback_exit_id', 'interval_seconds', 'threshold') if key in value}
                for identity, value in health.items()}
    return {'records': account_records, 'files': {str(path): file_observation(path) for path in sorted(paths, key=str)},
            'profiles': profiles, 'units': unit_files(units), 'firewall': firewall(), 'network_policy': network_policy(),
            'sysctl_aliases': sysctl_aliases, 'health_settings': settings,
            'services': {name: service(name) for name in sorted(service_names)},
            'data_attributes': {'uid': DATA.stat().st_uid, 'gid': DATA.stat().st_gid,
                                'mode': stat.S_IMODE(DATA.stat().st_mode)}}


def compare_snapshot(before, after, running):
    for key in ('records', 'profiles', 'units', 'firewall', 'network_policy', 'sysctl_aliases', 'health_settings'):
        require(before[key] == after[key], 'Protected ' + key + ' changed')
    require(set(before['files']) == set(after['files']), 'Protected file inventory changed')
    for path, observation in before['files'].items():
        current = after['files'][path]
        require(observation.get('exists') == current.get('exists') and observation.get('sha256') == current.get('sha256'),
                'Protected file bytes or existence changed: ' + path)
        if observation.get('exists'):
            if path in (str(DATA / 'hy2-server.crt.pem'), str(DATA / 'hy2-server.key.pem')):
                import grp
                allowed = {'uid': 0, 'gid': grp.getgrnam('hy2').gr_gid, 'mode': 0o640}
                require({key: current[key] for key in allowed} == allowed, 'TLS access permissions are invalid')
            else:
                require(observation == current, 'Protected file attributes changed: ' + path)
    import grp
    require(after['data_attributes'] == {'uid': 0, 'gid': grp.getgrnam('hy2').gr_gid, 'mode': 0o710},
            'Panel/HY2 data access permissions are invalid')
    for name, value in before['services'].items():
        current = after['services'][name]
        if name == PANEL:
            require(current['UnitFileState'] == value['UnitFileState'], 'Panel enablement changed')
            require(current['ActiveState'] == ('active' if running else 'inactive'), 'Panel lifecycle differs')
        else:
            require(value == current, 'Unrelated service state or proxy epoch changed: ' + name)


def ledger():
    path = safe(DATA / 'traffic.private.json', True)
    value = json.loads(path.read_text(encoding='utf-8'))
    require(value.get('version') == 1 and isinstance(value.get('users'), dict), 'Invalid traffic ledger')
    return value


def compare_ledger(before, after):
    require(set(before['users']) == set(after['users']), 'Traffic identity set changed')
    for identity, item in before['users'].items():
        current = after['users'][identity]
        require(all(item.get(key) == current.get(key) for key in ('quota_bytes', 'rate_bps')), 'Traffic limits changed')
        for month, totals in item.get('months', {}).items():
            require(month in current.get('months', {}) and all(type(current['months'][month].get(key)) is int
                    and current['months'][month][key] >= totals[key] for key in ('up_bytes', 'down_bytes')),
                    'Monthly traffic cumulative decreased')
        require(item.get('epoch') == current.get('epoch'), 'Legacy traffic epoch changed')
        if item.get('sample_time') is not None:
            require(type(current.get('sample_time')) in (int, float)
                    and current['sample_time'] >= item['sample_time'], 'Legacy traffic sample timestamp decreased')
        for counter, amount in item.get('counters', {}).items():
            require(type(current.get('counters', {}).get(counter)) is int
                    and current['counters'][counter] >= amount, 'Legacy traffic counter decreased')
        for source, values in item.get('sources', {}).items():
            updated = current.get('sources', {}).get(source, {})
            if values.get('epoch') is not None:
                require(updated.get('epoch') == values['epoch'], 'Traffic source epoch changed')
            if values.get('sample_time') is not None:
                require(type(updated.get('sample_time')) in (int, float)
                        and updated['sample_time'] >= values['sample_time'], 'Traffic source sample timestamp decreased')
            for counter, amount in values.get('counters', {}).items():
                require(type(updated.get('counters', {}).get(counter)) is int
                        and updated['counters'][counter] >= amount, 'Traffic source counter decreased')


def source_name(name):
    require(isinstance(name, str) and '\\' not in name, 'Invalid source path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and all(part not in ('.', '..', '__pycache__', 'vendor') for part in path.parts)
            and '.private.' not in name and path.suffix not in ('.pyc', '.pem'), 'Unsafe managed source path')
    require(name in ('configure_reality.py', 'configure_static_exits.py', 'test_configure_reality.py', 'test_configure_static_exits.py')
            or (len(path.parts) >= 2 and path.parts[0] == 'panel' and path.suffix in ('.py', '.json', '.yaml', '.js', '.css', '.html', '.svg')),
            'Unmanaged source file')
    return path


def unpack(stage, configuration):
    manifest_bytes = safe(stage / 'release-manifest.json', True).read_bytes()
    require(sha(manifest_bytes) == configuration['manifest_sha256'], 'Remote manifest hash differs')
    manifest = json.loads(manifest_bytes.decode('utf-8'))
    require(all(manifest.get(key) == configuration.get(key) for key in
                ('format', 'deployment_ip', 'release_files', 'release_sha256', 'archive_sha256')),
            'Remote manifest and release index differ')
    names, hashes = configuration['release_files'], configuration['release_sha256']
    require(isinstance(names, list) and isinstance(hashes, dict) and len(names) == len(set(names))
            and set(names) == set(hashes) and all(valid_hash(value) for value in hashes.values()), 'Invalid release index')
    for name in names:
        source_name(name)
    archive = safe(stage / 'release.tar.gz', True)
    require(sha(archive.read_bytes()) == configuration['archive_sha256'], 'Remote archive hash differs')
    contents = {}
    with tarfile.open(str(archive), 'r:gz') as bundle:
        members = bundle.getmembers()
        require(len(members) == len(names) and {item.name for item in members} == {'release/' + name for name in names}
                and all(item.isfile() and 0 <= item.size < 30 * 1024 * 1024 for item in members)
                and sum(item.size for item in members) < 30 * 1024 * 1024, 'Unsafe source archive')
        for item in members:
            name = item.name[len('release/'):]
            payload = bundle.extractfile(item).read()
            require(sha(payload) == hashes[name], 'Frozen remote source changed')
            if name.endswith('.py'):
                compile(payload, name, 'exec')
            contents[name] = payload
    return contents


def baseline_check(configuration):
    expected = configuration['baseline_sha256']
    require(isinstance(expected, dict) and all(valid_hash(value) for value in expected.values()), 'Invalid baseline index')
    drift = []
    for name in sorted(set(expected) | set(configuration['release_files'])):
        source_name(name)
        path = safe(APP / name, True, missing=True)
        actual = sha(path.read_bytes()) if path.exists() else None
        if actual != expected.get(name):
            drift.append({'path': name, 'expected_sha256': expected.get(name), 'actual_sha256': actual})
    return drift


def bytecode(paths):
    removed = []
    for name in paths:
        if not name.endswith('.py'):
            continue
        source = APP / name
        candidates = [source.with_suffix('.pyc')]
        directory = safe(source.parent / '__pycache__', missing=True)
        if directory.exists():
            require(directory.is_dir(), 'Unexpected bytecode cache directory')
            candidates += list(directory.glob(source.stem + '.*.pyc'))
        for path in candidates:
            safe(path, True, missing=True)
            if path.exists():
                require(APP in path.parents and 'vendor' not in path.relative_to(APP).parts, 'Bytecode boundary differs')
                path.unlink()
                removed.append(str(path.relative_to(APP)))
    return removed


def ready():
    deadline = time.time() + 35
    while time.time() < deadline:
        try:
            status, unused, body = api('/api/session', 'https://198-200-49-63.sslip.io:8443')
            if status == 200 and body.get('authenticated') is False and service(PANEL)['ActiveState'] == 'active':
                return
        except Exception:
            pass
        time.sleep(.4)
    raise RuntimeError('Panel did not become ready')


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def validate_journal(stage, journal):
    require(isinstance(journal, dict) and journal.get('format') == FORMAT
            and valid_hash(journal.get('archive_sha256')) and isinstance(journal.get('entries'), list)
            and journal.get('phase') in ('prepared', 'installing', 'starting', 'complete', 'rolled-back'),
            'Invalid rollback transaction')
    for key in ('baseline_sha256', 'release_sha256'):
        require(isinstance(journal.get(key), dict) and all(valid_hash(value) for value in journal[key].values()),
                'Invalid rollback full-source index')
        for name in journal[key]:
            source_name(name)
    seen = set()
    for index, entry in enumerate(journal['entries']):
        require(isinstance(entry, dict) and set(entry) ==
                {'name', 'before_sha256', 'after_sha256', 'attributes', 'backup'}, 'Invalid code checkpoint entry')
        source_name(entry['name'])
        require(entry['name'] not in seen and valid_hash(entry['after_sha256'])
                and (entry['before_sha256'] is None or valid_hash(entry['before_sha256'])), 'Invalid rollback code index')
        seen.add(entry['name'])
        if entry['before_sha256'] is None:
            require(entry['backup'] is None and entry['attributes'] is None
                    and safe(stage / 'code-before' / (str(index) + '.missing'), True).read_bytes() == b'Previously absent\n',
                    'Absent-file checkpoint differs')
        else:
            info = entry['attributes']
            require(isinstance(info, dict) and set(info) == {'mode', 'uid', 'gid', 'atime_ns', 'mtime_ns'}
                    and all(type(value) is int and value >= 0 for value in info.values())
                    and info['mode'] <= 0o7777 and entry['backup'] == 'code-before/' + str(index) + '.source',
                    'Invalid original-file checkpoint')
            require(sha(safe(stage / entry['backup'], True).read_bytes()) == entry['before_sha256'],
                    'Code checkpoint hash differs')
        path = safe(APP / entry['name'], True, missing=True)
        actual = sha(path.read_bytes()) if path.exists() else None
        require(actual in (entry['before_sha256'], entry['after_sha256']), 'Concurrent source edit prevents rollback')
        require(entry['before_sha256'] == journal['baseline_sha256'].get(entry['name'])
                and entry['after_sha256'] == journal['release_sha256'].get(entry['name']), 'Rollback source binding differs')
    for name in set(journal['baseline_sha256']) | set(journal['release_sha256']):
        if name not in seen:
            path = safe(APP / name, True, missing=True)
            actual = sha(path.read_bytes()) if path.exists() else None
            require(actual == journal['baseline_sha256'].get(name) == journal['release_sha256'].get(name),
                    'Concurrent unchanged source edit prevents rollback')


def rollback(stage, journal):
    validate_journal(stage, journal)
    run(['systemctl', 'stop', PANEL])
    require(service(PANEL)['ActiveState'] == 'inactive', 'Cannot stop candidate panel')
    for entry in reversed(journal['entries']):
        path = safe(APP / entry['name'], True, missing=True)
        actual = sha(path.read_bytes()) if path.exists() else None
        require(actual in (entry['before_sha256'], entry['after_sha256']), 'Concurrent source edit prevents rollback')
        if actual == entry['before_sha256']:
            continue
        if entry['before_sha256'] is None:
            path.unlink()
        else:
            original = safe(stage / entry['backup'], True).read_bytes()
            require(sha(original) == entry['before_sha256'], 'Code checkpoint hash differs')
            atomic(path, original, entry['attributes'])
    bytecode([entry['name'] for entry in journal['entries']])
    require(not baseline_check({'baseline_sha256': journal['baseline_sha256'],
                                'release_files': list(journal['release_sha256'])}), 'Restored full-source baseline differs')
    run(['systemctl', 'start', PANEL])
    ready()
    require(not baseline_check({'baseline_sha256': journal['baseline_sha256'],
                                'release_files': list(journal['release_sha256'])}), 'Rollback startup changed restored source')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    require(os.name == 'posix' and os.geteuid() == 0 and sys.version_info[:2] == (3, 6), 'Root production Python 3.6 required')
    stage = safe(args.stage)
    require(stage.parent == Path('/root') and re.fullmatch(r'vps-console-deploy-[A-Za-z0-9_-]+', stage.name)
            and stage.is_dir() and stage.stat().st_uid == 0 and stat.S_IMODE(stage.stat().st_mode) == 0o700,
            'Unsafe private deployment stage')
    safe(APP)
    safe(DATA)
    require(not LOCK.is_symlink(), 'Unsafe maintenance lock')
    descriptor = os.open(str(LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result = {'success': False, 'phase': 'preflight', 'stage': str(stage), 'production_updated': False}
    stopped, journal, before, before_ledger = False, None, None, None
    try:
        if args.rollback:
            journal = json.loads(safe(stage / 'transaction.private.json', True).read_text(encoding='utf-8'))
            validate_journal(stage, journal)
            before = json.loads(safe(stage / 'protected-before.private.json', True).read_text(encoding='utf-8'))
            before_ledger = json.loads(safe(stage / 'ledger-before.private.json', True).read_text(encoding='utf-8'))
            status = service(PANEL)['ActiveState']
            require(status in ('active', 'inactive'), 'Panel lifecycle is not quiet')
            compare_snapshot(before, snapshot(), status == 'active')
            compare_ledger(before_ledger, ledger())
            if status == 'active':
                credentials = json.load(sys.stdin).get('credentials', [])
                result['accounts_checked'] = quiescent(launch_context(), credentials)
                credentials.clear()
            stopped = True
            rollback(stage, journal)
            compare_snapshot(before, snapshot(), True)
            compare_ledger(before_ledger, ledger())
            journal['phase'] = 'rolled-back'
            write_json(stage / 'transaction.private.json', journal)
            result.update(success=True, phase='manual-rollback-complete', rollback_success=True)
            return result
        configuration = json.load(sys.stdin)
        require(configuration.get('format') == SOURCE_FORMAT and configuration.get('deployment_ip') == '198.200.49.63', 'Wrong frozen target')
        require(sha(safe(stage / 'deploy_remote.py', True).read_bytes()) == configuration['helper_sha256'],
                'Remote deployment helper hash differs')
        contents = unpack(stage, configuration)
        drift = baseline_check(configuration)
        if drift:
            result.update(phase='baseline-drift', drift=drift)
            return result
        context = launch_context()
        result['accounts_checked'] = quiescent(context, configuration['credentials'],
                                               configuration.get('allow_registry_preflight') is True)
        configuration['credentials'].clear()
        before, before_ledger = snapshot(), ledger()
        require(before['services']['raksmart-hy2.service']['ActiveState'] != 'active', 'Legacy HY2 unexpectedly active')
        write_json(stage / 'protected-before.private.json', before)
        write_json(stage / 'ledger-before.private.json', before_ledger)
        originals = stage / 'code-before'
        originals.mkdir(mode=0o700)
        entries = []
        for name, payload in sorted(contents.items()):
            path = safe(APP / name, True, missing=True)
            old = path.read_bytes() if path.exists() else None
            if old == payload:
                continue
            entry = {'name': name, 'before_sha256': sha(old) if old is not None else None,
                     'after_sha256': sha(payload), 'attributes': attributes(path) if old is not None else None,
                     'backup': 'code-before/' + str(len(entries)) + '.source' if old is not None else None}
            if old is not None:
                atomic(stage / entry['backup'], old)
            else:
                atomic(originals / (str(len(entries)) + '.missing'), b'Previously absent\n')
            entries.append(entry)
        journal = {'format': FORMAT, 'archive_sha256': configuration['archive_sha256'], 'entries': entries, 'phase': 'prepared',
                   'baseline_sha256': configuration['baseline_sha256'], 'release_sha256': configuration['release_sha256']}
        write_json(stage / 'transaction.private.json', journal)
        result['changed_source_files'] = len(entries)
        result['phase'] = 'stop-panel'
        stopped = True
        run(['systemctl', 'stop', PANEL])
        compare_snapshot(before, snapshot(), False)
        compare_ledger(before_ledger, ledger())
        require(not baseline_check(configuration), 'Source drift after stopping panel')
        journal['phase'] = 'installing'
        write_json(stage / 'transaction.private.json', journal)
        for entry in entries:
            path = safe(APP / entry['name'], True, missing=True)
            # Every parent already belongs to the installed application tree.
            safe(path.parent)
            require(path.parent.is_dir(), 'New source parent is not installed')
            actual = sha(path.read_bytes()) if path.exists() else None
            require(actual == entry['before_sha256'], 'Concurrent edit before source replacement')
            info = entry['attributes'] or {'uid': 0, 'gid': 0, 'mode': 0o644, 'atime_ns': int(time.time() * 1e9),
                                            'mtime_ns': int(time.time() * 1e9)}
            atomic(path, contents[entry['name']], info)
        result['bytecode_removed'] = bytecode([entry['name'] for entry in entries])
        for name, expected in configuration['release_sha256'].items():
            require(sha(safe(APP / name, True).read_bytes()) == expected, 'Installed source hash differs')
        compare_snapshot(before, snapshot(), False)
        compare_ledger(before_ledger, ledger())
        journal['phase'] = 'starting'
        write_json(stage / 'transaction.private.json', journal)
        result['phase'] = 'start-panel'
        run(['systemctl', 'start', PANEL])
        ready()
        after = snapshot()
        compare_snapshot(before, after, True)
        compare_ledger(before_ledger, ledger())
        for name, expected in configuration['release_sha256'].items():
            require(sha(safe(APP / name, True).read_bytes()) == expected, 'Startup changed installed source')
        write_json(stage / 'protected-after.private.json', after)
        write_json(stage / 'ledger-after.private.json', ledger())
        journal['phase'] = 'complete'
        write_json(stage / 'transaction.private.json', journal)
        result.update(success=True, phase='complete', production_updated=True, only_panel_restarted=True,
                      protected_bytes_preserved=True, proxy_epochs_preserved=True, traffic_cumulative_non_decreasing=True,
                      archive_sha256=configuration['archive_sha256'], panel_enablement_preserved=True)
    except BaseException as error:
        result.update(error_type=type(error).__name__, failure=str(error) if isinstance(error, RuntimeError) else 'Deployment transaction failed')
        if stopped and journal is not None and not args.rollback:
            try:
                rollback(stage, journal)
                compare_snapshot(before, snapshot(), True)
                compare_ledger(before_ledger, ledger())
                result['rollback_success'] = True
                journal['phase'] = 'rolled-back'
                write_json(stage / 'transaction.private.json', journal)
            except BaseException as rollback_error:
                result.update(rollback_success=False, rollback_incomplete=True,
                              rollback_error_type=type(rollback_error).__name__)
        elif stopped and args.rollback:
            result.update(rollback_success=False, rollback_incomplete=True)
    finally:
        os.close(descriptor)
        write_json(stage / 'report.json', result)
    return result


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    try:
        result = main()
    except BaseException as error:
        result = {'success': False, 'error_type': type(error).__name__, 'failure': 'Deployment stopped before transaction initialization'}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result.get('success') else 1)
