"""Python 3.6 first adoption transaction for the console on one reviewed host.

Credentials arrive on SSH stdin. Private data stays in memory or 0600
checkpoints. No application imports or host actions run when this is imported.
"""
import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time

try:
    import grp
except ImportError:  # Local fixture review on Windows; never used on a host.
    grp = None

APP = Path('/opt/vps-panel')
DATA = Path('/var/lib/vps-panel')
XRAY_CONFIG = Path('/usr/local/etc/xray/config.json')
HY2_ROOT = Path('/usr/local/etc/raksmart-hy2')
MEMBERS = Path('/usr/local/etc/xray-members')
SYSTEMD = Path('/etc/systemd/system')
CADDY_CONFIG = Path('/etc/caddy/Caddyfile')
PANEL = 'vps-panel.service'
LEGACY = 'raksmart-hy2.service'
OWNER_HY2 = 'raksmart-hy2@443.service'
LOCK = Path('/run/lock/vps-console-adoption-deploy.lock')
FORMAT = 'vps-console-adoption-transaction-v1'
SOURCE_FORMAT = 'vps-console-optimization-release-v1'

XRAY_TEMPLATE = '''[Unit]
Description=Independent VPS console Xray instance %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/usr/local/etc/xray-members/%i
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray-members/%i/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
'''
HY2_TEMPLATE = '''[Unit]
Description=RAKsmart account Hysteria 2 UDP %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hy2
Group=hy2
WorkingDirectory=/usr/local/etc/raksmart-hy2
Environment=QUIC_GO_DISABLE_GSO=1
Environment=QUIC_GO_DISABLE_ECN=1
ExecStart=/usr/local/bin/raksmart-hysteria2 server --config /usr/local/etc/raksmart-hy2/accounts/%i.yaml
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
UMask=0027

[Install]
WantedBy=multi-user.target
'''
PANEL_DROPIN = '''[Service]
ReadWriteDirectories=/usr/local/etc/xray-members /usr/local/etc/raksmart-hy2/accounts
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
RestrictAddressFamilies=AF_NETLINK
'''
ASSETS = {
    '/etc/systemd/system/xray-panel@.service': XRAY_TEMPLATE,
    '/etc/systemd/system/raksmart-hy2@.service': HY2_TEMPLATE,
    '/etc/systemd/system/vps-panel.service.d/90-console-adoption.conf': PANEL_DROPIN,
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def safe(path, regular=False, missing=False):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Canonical absolute path required')
    require(all(not part.is_symlink() for part in [path] + list(path.parents)), 'Linked host path rejected')
    require(missing or path.exists(), 'Required host path missing: ' + str(path))
    if path.exists() and regular:
        require(path.is_file() and stat.S_ISREG(path.stat().st_mode), 'Regular host file required')
    return path


def info(path):
    item = safe(path).stat()
    return {'mode': stat.S_IMODE(item.st_mode), 'uid': item.st_uid, 'gid': item.st_gid,
            'atime_ns': item.st_atime_ns, 'mtime_ns': item.st_mtime_ns}


def atomic(path, payload, attributes=None):
    path = safe(path, True, True)
    safe(path.parent)
    temporary = path.with_name('.' + path.name + '.console-adoption-' + secrets.token_hex(8))
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            if attributes:
                os.fchown(stream.fileno(), attributes['uid'], attributes['gid'])
                os.fchmod(stream.fileno(), attributes['mode'])
        if attributes:
            os.utime(str(temporary), ns=(attributes['atime_ns'], attributes['mtime_ns']))
        os.replace(str(temporary), str(path))
        directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_json(path, value):
    atomic(path, json_bytes(value))


def default_info(mode=0o644, gid=0):
    now = int(time.time() * 1000000000)
    return {'uid': 0, 'gid': gid, 'mode': mode, 'atime_ns': now, 'mtime_ns': now}


def run(args, check=True, timeout=25):
    environment = os.environ.copy()
    environment['LC_ALL'] = 'C'
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, env=environment)
    require(not check or result.returncode == 0, 'Host command failed: ' + Path(args[0]).name)
    return result


def service(name):
    result = run(['systemctl', 'show', name, '--property=LoadState', '--property=ActiveState',
                  '--property=SubState', '--property=MainPID', '--property=UnitFileState',
                  '--property=FragmentPath', '--property=ExecMainStartTimestampMonotonic'], False)
    fields = dict(line.split('=', 1) for line in result.stdout.decode('utf-8', 'replace').splitlines()
                  if '=' in line)
    require('LoadState' in fields and 'ActiveState' in fields, 'Incomplete service observation')
    return fields


def api(path, origin, data=None, session=None):
    connection = http.client.HTTPConnection('127.0.0.1', 18787, timeout=10)
    headers = {'Origin': origin}
    if data is not None:
        headers['Content-Type'] = 'application/json'
    if session:
        headers.update({'Cookie': session['cookie'], 'X-CSRF-Token': session['csrf']})
    try:
        connection.request('GET' if data is None else 'POST', path,
                           None if data is None else json.dumps(data), headers)
        response = connection.getresponse()
        payload = response.read(2 * 1024 * 1024)
        return response.status, dict(response.getheaders()), json.loads(payload.decode('utf-8'))
    finally:
        connection.close()


def launch_context(configuration):
    observed = service(PANEL)
    require(observed['ActiveState'] == 'active' and int(observed.get('MainPID', 0)) > 0,
            'The panel must be running before adoption')
    argv = safe('/proc/' + observed['MainPID'] + '/cmdline', True).read_bytes().decode('utf-8').split('\0')
    require(str(APP / 'panel/server.py') in argv, 'Unexpected panel executable')
    def argument(name, default=None):
        require(argv.count(name) <= 1, 'Repeated panel launch option')
        return argv[argv.index(name) + 1] if name in argv else default
    require(argument('--directory', str(DATA)) == str(DATA)
            and argument('--config', str(XRAY_CONFIG)) == str(XRAY_CONFIG)
            and argument('--public-ip') == configuration['deployment_ip']
            and argument('--origin') == configuration['origin']
            and argument('--port', '18787') == '18787'
            and argument('--base-path', '/node-console/') == '/node-console/',
            'Running panel target or paths differ')
    return observed


def login_idle(configuration, migrated=False):
    auth = json.loads(safe(DATA / 'auth.private.json', True).read_text(encoding='utf-8'))
    matches = [item for item in configuration['credentials'] if item.get('username') == auth['username']]
    require(len(matches) == 1, 'The existing administrator login is required')
    status, headers, body = api('/api/login', configuration['origin'], matches[0])
    require(status == 200, 'Administrator preflight login failed')
    session = {'cookie': headers['Set-Cookie'].split(';', 1)[0], 'csrf': body['csrf']}
    try:
        status, unused, state = api('/api/state', configuration['origin'], session=session)
        require(status == 200 and state.get('server_ip') == configuration['deployment_ip'],
                'Administrator state preflight failed')
        require(not state.get('job') or state['job'].get('status') != 'running', 'An exit job is running')
        require(not state.get('health', {}).get('checking')
                and state.get('health', {}).get('mode', 'manual') == 'manual', 'Health operations are not quiet')
        if migrated:
            status, unused, body = api('/api/users/provision', configuration['origin'], session=session)
            require(status == 200 and not any(item.get('status') in ('queued', 'running')
                    for item in body.get('tasks', [])), 'Member preparation is not quiet')
            status, unused, body = api('/api/users', configuration['origin'], session=session)
            require(status == 200 and len(body.get('users', [])) == 1
                    and body['users'][0].get('service_active') is True
                    and body['users'][0].get('hy2_service_active') is True,
                    'Migrated owner protocol status is unavailable')
            status, unused, body = api('/api/entrances', configuration['origin'], session=session)
            require(status == 200 and body['entrances']['available_count'] == 2,
                    'Default member entrances are unavailable')
        return True
    finally:
        api('/api/logout', configuration['origin'], {}, session)


def source_name(name):
    require(isinstance(name, str) and '\\' not in name, 'Invalid source name')
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and all(part not in ('.', '..', '__pycache__', 'vendor')
            for part in path.parts) and '.private.' not in name and path.suffix not in ('.pyc', '.pem'),
            'Unsafe source name')
    require(name in ('configure_reality.py', 'configure_static_exits.py', 'test_configure_reality.py',
                    'test_configure_static_exits.py')
            or (len(path.parts) >= 2 and path.parts[0] == 'panel'
                and path.suffix in ('.py', '.json', '.yaml', '.js', '.css', '.html', '.svg')),
            'Unmanaged source name')
    return path


def vendor_name(name):
    require(isinstance(name, str) and '\\' not in name, 'Invalid dependency name')
    path = PurePosixPath(name)
    require(str(path) == name and len(path.parts) >= 2 and path.parts[0] == 'vendor'
            and not path.is_absolute() and all(part not in ('.', '..', '__pycache__') for part in path.parts)
            and '.private.' not in name and path.suffix != '.pyc', 'Unsafe dependency name')
    return path


def archive_contents(path, prefix, hashes, budget):
    require(isinstance(hashes, dict) and hashes and all(valid_hash(value) for value in hashes.values()),
            'Invalid archive file index')
    result = {}
    with tarfile.open(str(safe(path, True)), 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len(hashes) and len(members) == len({item.name for item in members})
                and {item.name for item in members} == {prefix + name for name in hashes}
                and all(item.isfile() and 0 <= item.size <= budget for item in members)
                and sum(item.size for item in members) <= budget, 'Unsafe archive inventory')
        for item in members:
            name = item.name[len(prefix):]
            (vendor_name if name.startswith('vendor/') else source_name)(name)
            payload = archive.extractfile(item).read()
            require(sha(payload) == hashes[name], 'Archived payload hash differs')
            if name.endswith('.py'):
                compile(payload, name, 'exec')
            result[name] = payload
    return result


def unpack(stage, configuration):
    manifest_data = safe(stage / 'release-manifest.json', True).read_bytes()
    require(sha(manifest_data) == configuration['manifest_sha256'], 'Remote manifest hash differs')
    manifest = json.loads(manifest_data.decode('utf-8'))
    for key in ('format', 'deployment_ip', 'origin', 'release_files', 'release_sha256',
                'baseline_sha256', 'archive_sha256', 'vendor_files', 'vendor_sha256', 'vendor_archive_sha256'):
        require(manifest.get(key) == configuration.get(key), 'Remote manifest binding differs')
    require(set(configuration['release_files']) == set(configuration['release_sha256'])
            and len(configuration['release_files']) == len(set(configuration['release_files'])),
            'Invalid source inventory')
    require(set(configuration['vendor_files']) == set(configuration['vendor_sha256'])
            and len(configuration['vendor_files']) == len(set(configuration['vendor_files'])),
            'Invalid dependency inventory')
    require(sha(safe(stage / 'release.tar.gz', True).read_bytes()) == configuration['archive_sha256']
            and sha(safe(stage / 'vendor.tar.gz', True).read_bytes()) == configuration['vendor_archive_sha256'],
            'Remote archive hash differs')
    sources = archive_contents(stage / 'release.tar.gz', 'release/', configuration['release_sha256'],
                               32 * 1024 * 1024)
    vendors = archive_contents(stage / 'vendor.tar.gz', '',
                               {'vendor/' + name: value for name, value in configuration['vendor_sha256'].items()},
                               128 * 1024 * 1024)
    root = stage / 'candidate'
    root.mkdir(mode=0o700)
    for name, payload in dict(sources, **vendors).items():
        destination = root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic(destination, payload, default_info())
    return sources, vendors, root


def baseline_check(configuration):
    expected = configuration['baseline_sha256']
    require(isinstance(expected, dict) and expected and all(valid_hash(value) for value in expected.values()),
            'Invalid production source baseline')
    drift = []
    for name in sorted(set(expected) | set(configuration['release_files'])):
        source_name(name)
        path = safe(APP / name, True, True)
        actual = sha(path.read_bytes()) if path.exists() else None
        if actual != expected.get(name):
            drift.append({'path': name, 'expected_sha256': expected.get(name), 'actual_sha256': actual})
    return drift


def observation(path):
    path = safe(path, True, True)
    if not path.exists():
        return {'exists': False}
    attributes = info(path)
    return {'exists': True, 'sha256': sha(path.read_bytes()),
            'uid': attributes['uid'], 'gid': attributes['gid'], 'mode': attributes['mode']}


def firewall():
    result = {}
    for args in (['iptables-save'], ['ip6tables-save'], ['nft', 'list', 'ruleset'],
                 ['firewall-cmd', '--state']):
        if not shutil.which(args[0]):
            continue
        response = run(args, False)
        payload = b'\n'.join(line for line in response.stdout.splitlines() if not line.startswith(b'#'))
        payload = re.sub(br'\[[0-9]+:[0-9]+\]', b'[counter]', payload)
        payload = re.sub(br'counter packets [0-9]+ bytes [0-9]+', b'counter packets COUNTER bytes COUNTER', payload)
        result[args[0]] = {'returncode': response.returncode, 'sha256': sha(payload)}
    require('iptables-save' in result, 'Firewall observation unavailable')
    return result


def network():
    result = {}
    for key in ('net.ipv4.tcp_congestion_control', 'net.core.default_qdisc', 'net.core.rmem_max',
                'net.core.wmem_max'):
        result[key] = run(['sysctl', '-n', key]).stdout.decode('utf-8').strip()
    for kind in ('qdisc', 'class'):
        result['tc:' + kind] = sha(run(['tc', kind, 'show']).stdout)
    for name in sorted(os.listdir('/sys/class/net')):
        require(re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}', name), 'Invalid network interface')
        result['filter:' + name] = sha(run(['tc', 'filter', 'show', 'dev', name]).stdout)
    return result


def protected_snapshot():
    paths = {
        DATA / 'auth.private.json', DATA / 'base.private.yaml', APP / 'install-marker.json',
        HY2_ROOT / 'server.yaml', HY2_ROOT / 'server.crt.pem', HY2_ROOT / 'server.key.pem',
        Path('/etc/resolv.conf'), Path('/usr/local/bin/xray'), Path('/usr/local/bin/raksmart-hysteria2'),
        Path('/etc/sysctl.conf'),
    }
    for root in (Path('/etc/caddy'),):
        for path in safe(root).rglob('*'):
            safe(path)
            if path.is_file():
                paths.add(path)
    # ACME bookkeeping may grow; retain the current HTTPS certificate/key bytes.
    certificate_root = safe('/var/lib/caddy/storage/certificates', missing=True)
    if certificate_root.exists():
        for path in certificate_root.rglob('*'):
            safe(path)
            if path.is_file() and path.suffix in ('.crt', '.key', '.pem'):
                paths.add(path)
    for name in (PANEL, 'xray.service', LEGACY, 'caddy.service'):
        for root in (SYSTEMD, Path('/usr/lib/systemd/system')):
            path = root / name
            if path.exists():
                paths.add(path)
            dropins = safe(root / (name + '.d'), missing=True)
            if dropins.exists():
                for child in dropins.rglob('*'):
                    safe(child)
                    if child.is_file() and str(child) not in ASSETS:
                        paths.add(child)
    sysctl_links = {}
    for path in safe('/etc/sysctl.d').glob('*.conf'):
        if path.is_symlink():
            require(path.name == '99-sysctl.conf' and os.readlink(str(path)) == '../sysctl.conf',
                    'Unknown sysctl alias')
            sysctl_links[str(path)] = {'target': os.readlink(str(path)), 'sha256': sha(safe('/etc/sysctl.conf', True).read_bytes())}
        else:
            paths.add(safe(path, True))
    return {'files': {str(path): observation(path) for path in sorted(paths, key=str)},
            'sysctl_links': sysctl_links, 'firewall': firewall(), 'network': network(),
            'services': {name: service(name) for name in (PANEL, 'xray.service', LEGACY, 'caddy.service')}}


def compare_protected(before, after, rollback=False, expected_caddy_sha256=None):
    before_files = copy.deepcopy(before['files'])
    if expected_caddy_sha256 is not None:
        require(valid_hash(expected_caddy_sha256), 'Invalid allowed Caddy hash')
        before_files[str(CADDY_CONFIG)]['sha256'] = expected_caddy_sha256
    require(before_files == after['files'], 'Protected host files changed')
    for key in ('sysctl_links', 'firewall', 'network'):
        require(before[key] == after[key], 'Protected host ' + key + ' changed')
    require(before['services']['caddy.service'] == after['services']['caddy.service'],
            'Caddy state or process epoch changed')
    for name in (PANEL, 'xray.service'):
        require(after['services'][name]['ActiveState'] == 'active'
                and after['services'][name].get('UnitFileState') == before['services'][name].get('UnitFileState'),
                'Existing service activity or enablement changed')
    legacy = after['services'][LEGACY]
    if rollback:
        require(legacy['ActiveState'] == before['services'][LEGACY]['ActiveState']
                and legacy.get('UnitFileState') == before['services'][LEGACY].get('UnitFileState'),
                'Legacy HY2 was not restored')
    else:
        require(legacy['ActiveState'] == 'inactive' and legacy.get('UnitFileState') == 'disabled',
                'Legacy HY2 did not relinquish UDP443')


def state_preserved(before, after):
    allowed = {'managed_hash', 'profile', 'profile_token', 'profile_version', 'profile_hash', 'profile_updated'}
    require({key: value for key, value in before.items() if key not in allowed}
            == {key: value for key, value in after.items() if key not in allowed},
            'Existing identities, rules, drafts, exit selection or history changed')
    if before.get('profile_token') is not None:
        require(before['profile_token'] == after.get('profile_token'), 'Existing profile capability changed')


def ledger():
    path = safe(DATA / 'traffic.private.json', True, True)
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else {'version': 1, 'users': {}}


def compare_ledger(before, after):
    require(before.get('version') == after.get('version') == 1 and isinstance(after.get('users'), dict),
            'Traffic ledger format changed')
    require(set(before['users']) <= set(after['users']), 'Traffic identity disappeared')
    for identity, item in before['users'].items():
        current = after['users'][identity]
        require(all(item.get(key) == current.get(key) for key in ('quota_bytes', 'rate_bps')),
                'Existing traffic limits changed')
        for month, totals in item.get('months', {}).items():
            require(month in current.get('months', {}) and all(type(current['months'][month].get(key)) is int
                    and current['months'][month][key] >= totals[key] for key in ('up_bytes', 'down_bytes')),
                    'Cumulative traffic decreased')


def legacy_values(payload):
    """Read only the generated legacy YAML fields; no general YAML parser."""
    text = payload.decode('utf-8')
    require('\t' not in text and '&' not in text and '*' not in text, 'Legacy HY2 YAML needs review')
    def section(name):
        found = re.search(r'^' + re.escape(name) + r':\s*\n((?:  [^\n]*\n?)+)', text, re.M)
        require(found is not None, 'Legacy HY2 field missing')
        result = {}
        for line in found.group(1).splitlines():
            match = re.fullmatch(r'  ([A-Za-z_]+): ([^\n]+)', line)
            require(match is not None and match.group(1) not in result, 'Legacy HY2 section needs review')
            value = match.group(2).strip()
            if value.startswith('"'):
                value = json.loads(value)
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1]
            result[match.group(1)] = value
        return result
    auth, tls = section('auth'), section('tls')
    require(set(auth) == {'type', 'password'} and auth['type'] == 'password'
            and re.fullmatch(r'[A-Za-z0-9_-]{43,128}', auth['password']), 'Legacy HY2 auth is unsupported')
    require(tls == {'cert': str(HY2_ROOT / 'server.crt.pem'), 'key': str(HY2_ROOT / 'server.key.pem')}
            and re.search(r'^listen: [\'"]?0\.0\.0\.0:443[\'"]?\s*$', text, re.M), 'Legacy HY2 TLS/listen differs')
    return auth['password']


def caddy_backup_limit(payload):
    text = payload.decode('utf-8')
    marker = '\thandle_path /node-console/* {'
    require(text.count(marker) == 1 and '/node-console/api/backups/preview' not in text
            and text.count('max_size 64KB') == 1, 'Existing Caddy request limit needs review')
    newline = '\r\n' if '\r\n' in text else '\n'
    addition = '\n'.join([
        '\thandle /node-console/api/backups/preview {',
        '\t\turi strip_prefix /node-console',
        '\t\trequest_body {',
        '\t\t\tmax_size 48MB',
        '\t\t}',
        '\t\treverse_proxy 127.0.0.1:18787 {',
        '\t\t\theader_up X-Real-IP {remote_host}',
        '\t\t}',
        '\t}', '',
    ]).replace('\n', newline) + newline
    candidate = text.replace(marker, addition + marker, 1).encode('utf-8')
    require(candidate.replace(addition.encode('utf-8'), b'', 1) == payload,
            'Unrelated Caddy directives changed')
    return candidate


def migration_payloads(configuration, candidate):
    sys.path.insert(0, str(candidate / 'vendor'))
    sys.path.insert(0, str(candidate))
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from panel import hy2, telemetry, subscriptions, accelerated_client
    from panel.backups import encrypt, decrypt
    # Validate the installed dependency build before any live mutation.
    probe_key = os.urandom(32)
    probe = b'console-adoption-crypto-check'
    require(decrypt(encrypt(probe, master_key=probe_key), master_key=probe_key) == probe,
            'Candidate cryptography roundtrip failed')
    password = legacy_values(safe(HY2_ROOT / 'server.yaml', True).read_bytes())
    certificate = safe(HY2_ROOT / 'server.crt.pem', True).read_bytes()
    private_key = safe(HY2_ROOT / 'server.key.pem', True).read_bytes()
    cert = x509.load_pem_x509_certificate(certificate, default_backend())
    key = serialization.load_pem_private_key(private_key, None, default_backend())
    require(cert.public_key().public_numbers() == key.public_key().public_numbers(), 'HY2 key/certificate mismatch')
    pin = cert.fingerprint(hashes.SHA256()).hex()
    require(pin == configuration['certificate_sha256'], 'Reviewed HY2 certificate pin changed')
    registry = {'version': 1, 'enabled': True, 'certificate_sha256': pin,
                'sni': configuration['hy2_sni'], 'accounts': {'admin': hy2._entry(443)}}
    registry['accounts']['admin']['password'] = password
    hy2.validate_registry(registry)
    integration = object.__new__(hy2.Integration)
    integration.data = registry
    owner = type('Owner', (), {'directory': DATA})()
    integration.accounts = type('Context', (), {'owner_manager': owner})()
    old_state = json.loads(safe(DATA / 'state.private.json', True).read_text(encoding='utf-8'))
    original_config = safe(XRAY_CONFIG, True).read_bytes()
    require(old_state['managed_hash'] == sha(original_config), 'Administrator state/config binding differs')
    old_config = json.loads(original_config.decode('utf-8'))
    require(isinstance(old_state.get('profile'), str) and old_state['profile'], 'Existing applied profile required')
    augmented = telemetry.augment_config(old_config, 443)
    new_config, new_profile = integration.compose(augmented, old_state['profile'], 443,
                                                  configuration['deployment_ip'])
    integration.validate_running({'id': 'admin', 'port': 443}, new_config)
    old_primary, new_primary = copy.deepcopy(old_config['inbounds'][0]), copy.deepcopy(new_config['inbounds'][0])
    for old_client, new_client in zip(old_primary['settings']['clients'], new_primary['settings']['clients']):
        if not old_client.get('email'):
            old_client.pop('email', None)
            new_client.pop('email', None)
    require(old_primary == new_primary and old_config['outbounds'] == new_config['outbounds']
            and [rule for rule in new_config['routing']['rules'] if rule.get('inboundTag') != ['panel-hy2-socks']]
            == old_config['routing']['rules'], 'Migration changed a REALITY identity or existing routing')
    # compose changes only proxy/group sections; surrounding rule/DNS text stays byte-for-byte equal.
    old_start, unused, unused, unused = accelerated_client._section(old_state['profile'], 'proxies')
    unused, old_end, unused, unused = accelerated_client._section(old_state['profile'], 'proxy-groups')
    new_start, unused, unused, unused = accelerated_client._section(new_profile, 'proxies')
    unused, new_end, unused, unused = accelerated_client._section(new_profile, 'proxy-groups')
    require(old_state['profile'][:old_start] == new_profile[:new_start]
            and old_state['profile'][old_end:] == new_profile[new_end:], 'Profile rule/provider/DNS text changed')
    payload = json_bytes(new_config)
    state = copy.deepcopy(old_state)
    state.update(managed_hash=sha(payload), profile=new_profile)
    subscriptions.update_metadata(state, old_state)
    state_preserved(old_state, state)
    test_config = candidate.parent / 'candidate-xray.private.json'
    atomic(test_config, payload)
    run(['/usr/local/bin/xray', 'run', '-test', '-config', str(test_config)])
    group = grp.getgrnam('hy2').gr_gid
    values = {
        str(XRAY_CONFIG): (payload, info(XRAY_CONFIG)),
        str(DATA / 'state.private.json'): (json_bytes(state), info(DATA / 'state.private.json')),
        str(DATA / 'users.private.json'): (json_bytes({'version': 1, 'users': []}), default_info(0o600)),
        str(DATA / 'hy2.private.json'): (json_bytes(registry), default_info(0o600)),
        str(DATA / 'hy2-server.crt.pem'): (certificate, default_info(0o640, group)),
        str(DATA / 'hy2-server.key.pem'): (private_key, default_info(0o640, group)),
        str(HY2_ROOT / 'accounts/443.yaml'): (json_bytes(integration.config({'id': 'admin', 'port': 443})),
                                               default_info(0o640, group)),
    }
    return values, old_state


def first_adoption_preflight(configuration):
    for path in (DATA / 'users.private.json', DATA / 'hy2.private.json', DATA / 'entrance-pool.private.json',
                 DATA / 'member-tasks.private.json', DATA / 'hy2-server.crt.pem', DATA / 'hy2-server.key.pem',
                 APP / 'vendor', MEMBERS, HY2_ROOT / 'accounts'):
        require(not safe(path, missing=True).exists(), 'First-adoption destination already exists')
    for path in ASSETS:
        require(not safe(path, True, True).exists(), 'Adoption service asset already exists')
    require(service(LEGACY)['ActiveState'] == 'active' and service(LEGACY).get('UnitFileState') == 'enabled'
            and service('xray.service')['ActiveState'] == 'active'
            and service('caddy.service')['ActiveState'] == 'active', 'Original proxy/HTTPS services must be healthy')
    for name, expected in configuration['binary_sha256'].items():
        require(name in ('/usr/local/bin/xray', '/usr/local/bin/raksmart-hysteria2') and valid_hash(expected)
                and sha(safe(name, True).read_bytes()) == expected, 'Reviewed proxy binary differs')
    require(service(OWNER_HY2)['LoadState'] == 'not-found', 'Owner HY2 instance already exists')
    fromports = (15000 + 443, 15600 + 443, 18600 + 443)
    for kind, address, port in [(socket.SOCK_STREAM, '127.0.0.1', value) for value in fromports]:
        with socket.socket(socket.AF_INET, kind) as probe:
            probe.bind((address, port))
    for port in (1443, 2443):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as probe:
                probe.bind(('0.0.0.0', port))
    ledger_before = ledger()
    require(not ledger_before['users'], 'Existing traffic history requires an incremental migration')
    global_ipv6 = run(['ip', '-6', 'addr', 'show', 'scope', 'global']).stdout.strip()
    original_config = json.loads(safe(XRAY_CONFIG, True).read_text(encoding='utf-8'))
    require(not global_ipv6 or original_config['inbounds'][0].get('listen') == '0.0.0.0',
            'A global IPv6 ingress requires a separate reviewed quota migration')
    configuration['global_ipv6_address_present'] = bool(global_ipv6)
    return ledger_before


def managed_destination(path):
    path = safe(path, True, True)
    if APP in path.parents:
        name = path.relative_to(APP).as_posix()
        (vendor_name if name.startswith('vendor/') else source_name)(name)
    else:
        allowed = {XRAY_CONFIG, CADDY_CONFIG, DATA / 'state.private.json', DATA / 'users.private.json',
                   DATA / 'hy2.private.json', DATA / 'hy2-server.crt.pem', DATA / 'hy2-server.key.pem',
                   DATA / 'backup-key.private.bin', HY2_ROOT / 'accounts/443.yaml'}
        allowed.update(Path(name) for name in ASSETS)
        require(path in allowed, 'Destination outside adoption boundary')
    return path


def checkpoint(stage, payloads, configuration, before, old_state):
    current_state = json.loads(safe(DATA / 'state.private.json', True).read_text(encoding='utf-8'))
    require(current_state == old_state
            and sha(safe(XRAY_CONFIG, True).read_bytes()) == old_state['managed_hash'],
            'State or configuration changed while migration was prepared')
    require(not baseline_check(configuration), 'Production source changed while migration was prepared')
    originals = stage / 'before'
    originals.mkdir(mode=0o700)
    entries = []
    for name, pair in sorted(payloads.items()):
        path = managed_destination(name)
        payload, desired_info = pair
        old = path.read_bytes() if path.exists() else None
        if path == DATA / 'state.private.json':
            require(old is not None and json.loads(old.decode('utf-8')) == old_state,
                    'State changed before its private checkpoint')
        elif path == XRAY_CONFIG:
            require(old is not None and sha(old) == old_state['managed_hash'],
                    'Running config changed before its private checkpoint')
        elif APP in path.parents:
            relative = path.relative_to(APP).as_posix()
            expected = None if relative.startswith('vendor/') else configuration['baseline_sha256'].get(relative)
            require((sha(old) if old is not None else None) == expected,
                    'Source changed before its private checkpoint')
        elif path == CADDY_CONFIG:
            require(sha(old) == before['files'][str(CADDY_CONFIG)]['sha256'],
                    'Caddy changed before its private checkpoint')
        if old == payload:
            continue
        index = len(entries)
        backup = 'before/' + str(index) + '.private' if old is not None else None
        marker = 'before/' + str(index) + '.missing'
        if old is not None:
            atomic(stage / backup, old)
        else:
            atomic(stage / marker, b'Previously absent\n')
        entries.append({'path': name, 'before_sha256': sha(old) if old is not None else None,
                        'after_sha256': sha(payload), 'before_attributes': info(path) if old is not None else None,
                        'after_attributes': desired_info, 'backup': backup, 'missing_marker': marker})
    value = {'format': FORMAT, 'phase': 'prepared', 'configuration': {key: configuration[key] for key in (
        'deployment_ip', 'origin', 'baseline_sha256', 'release_sha256', 'release_files', 'vendor_sha256',
        'vendor_files', 'archive_sha256', 'certificate_sha256', 'hy2_sni')}, 'entries': entries,
        'directories': [], 'data_attributes': info(DATA), 'before': before, 'old_state_sha256': sha(json_bytes(old_state))}
    write_json(stage / 'transaction.private.json', value)
    return value


def ensure_parents(stage, journal, path):
    needed = []
    parent = path.parent
    while not parent.exists():
        safe(parent, missing=True)
        needed.append(parent)
        parent = parent.parent
    for directory in reversed(needed):
        require(directory in (MEMBERS, HY2_ROOT / 'accounts', SYSTEMD / (PANEL + '.d'), APP / 'vendor')
                or APP / 'vendor' in directory.parents, 'Unexpected new deployment directory')
        directory.mkdir(mode=0o755)
        if directory == HY2_ROOT / 'accounts':
            os.chown(str(directory), 0, grp.getgrnam('hy2').gr_gid)
            os.chmod(str(directory), 0o750)
        journal['directories'].append(str(directory))
        write_json(stage / 'transaction.private.json', journal)


def bytecode(entries):
    removed = []
    for entry in entries:
        path = Path(entry['path'])
        if APP not in path.parents or path.suffix != '.py' or APP / 'vendor' in path.parents:
            continue
        values = [path.with_suffix('.pyc')]
        directory = safe(path.parent / '__pycache__', missing=True)
        if directory.exists():
            values.extend(directory.glob(path.stem + '.*.pyc'))
        for candidate in values:
            safe(candidate, True, True)
            if candidate.exists():
                candidate.unlink()
                removed.append(str(candidate.relative_to(APP)))
    return removed


def wait_panel(origin):
    deadline = time.time() + 40
    while time.time() < deadline:
        try:
            status, unused, body = api('/api/session', origin)
            if status == 200 and body.get('authenticated') is False and service(PANEL)['ActiveState'] == 'active':
                return
        except Exception:
            pass
        time.sleep(.4)
    raise RuntimeError('Panel did not become ready')


def wait_proxies():
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            require(service('xray.service')['ActiveState'] == 'active'
                    and service(OWNER_HY2)['ActiveState'] == 'active', 'Migrated proxy not active')
            for port in (443, 15443, 16043, 19043):
                with socket.create_connection(('127.0.0.1', port), timeout=.4):
                    pass
            return
        except Exception:
            time.sleep(.4)
    raise RuntimeError('Migrated proxy entrances did not become ready')


def verify_installed(stage, journal, old_state, before_ledger):
    configuration = journal['configuration']
    for entry in journal['entries']:
        require(observation(entry['path']).get('sha256') == entry['after_sha256'],
                'Installed transaction payload differs')
    current = json.loads(safe(DATA / 'state.private.json', True).read_text(encoding='utf-8'))
    state_preserved(old_state, current)
    require(current['managed_hash'] == sha(safe(XRAY_CONFIG, True).read_bytes()), 'Migrated state/config binding differs')
    registry = json.loads(safe(DATA / 'hy2.private.json', True).read_text(encoding='utf-8'))
    require(registry['accounts']['admin']['password'] == legacy_values(safe(HY2_ROOT / 'server.yaml', True).read_bytes())
            and registry['certificate_sha256'] == configuration['certificate_sha256']
            and registry['sni'] == configuration['hy2_sni'], 'Original HY2 authentication or TLS identity changed')
    require(safe(DATA / 'hy2-server.crt.pem', True).read_bytes() == safe(HY2_ROOT / 'server.crt.pem', True).read_bytes()
            and safe(DATA / 'hy2-server.key.pem', True).read_bytes() == safe(HY2_ROOT / 'server.key.pem', True).read_bytes(),
            'HY2 TLS copies differ')
    for path in (DATA / 'entrance-pool.private.json', DATA / 'member-tasks.private.json'):
        require(not safe(path, True, True).exists(), 'Unused member pool/task storage was created')
    compare_ledger(before_ledger, ledger())
    after = protected_snapshot()
    caddy_entry = next(entry for entry in journal['entries'] if entry['path'] == str(CADDY_CONFIG))
    compare_protected(journal['before'], after, expected_caddy_sha256=caddy_entry['after_sha256'])
    for name, filename in ((OWNER_HY2, 'raksmart-hy2@.service'),
                           ('xray-panel@0123456789abcdef.service', 'xray-panel@.service')):
        observed = service(name)
        require(observed['LoadState'] == 'loaded' and observed.get('FragmentPath') == str(SYSTEMD / filename),
                'Adopted concrete instance does not load the reviewed template')
    require(service(OWNER_HY2).get('UnitFileState') == 'enabled', 'Owner HY2 is not enabled')
    write_json(stage / 'protected-after.private.json', after)
    write_json(stage / 'ledger-post-deployment.private.json', ledger())


def validate_rollback(stage, journal):
    require(journal.get('format') == FORMAT and isinstance(journal.get('entries'), list)
            and journal.get('phase') in ('prepared', 'installing', 'starting', 'complete', 'rolled-back'),
            'Invalid adoption rollback journal')
    paths = set()
    for index, entry in enumerate(journal['entries']):
        path = managed_destination(entry['path'])
        require(str(path) not in paths and valid_hash(entry['after_sha256']), 'Invalid rollback inventory')
        paths.add(str(path))
        actual = observation(path).get('sha256')
        require(actual in (entry['before_sha256'], entry['after_sha256']), 'Concurrent file edit prevents rollback')
        if entry['before_sha256'] is None:
            require(entry['backup'] is None and entry['missing_marker'] == 'before/' + str(index) + '.missing'
                    and safe(stage / entry['missing_marker'], True).read_bytes() == b'Previously absent\n',
                    'Missing-file checkpoint differs')
        else:
            require(valid_hash(entry['before_sha256']) and entry['backup'] == 'before/' + str(index) + '.private'
                    and sha(safe(stage / entry['backup'], True).read_bytes()) == entry['before_sha256'],
                    'Private checkpoint hash differs')
    # Nontransactional source bytes must also remain equal to their reviewed baseline.
    for name, expected in journal['configuration']['baseline_sha256'].items():
        path = APP / name
        if str(path) not in paths:
            require(sha(safe(path, True).read_bytes()) == expected, 'Concurrent unchanged source edit prevents rollback')
    if (DATA / 'users.private.json').exists():
        registry = json.loads(safe(DATA / 'users.private.json', True).read_text(encoding='utf-8'))
        require(not registry.get('users'), 'Created members prevent first-adoption rollback')


def rollback(stage, journal):
    validate_rollback(stage, journal)
    for name in (PANEL, 'xray.service'):
        run(['systemctl', 'stop', name])
    run(['systemctl', 'stop', OWNER_HY2], False)
    require(service(OWNER_HY2)['ActiveState'] != 'active', 'Candidate HY2 could not be stopped')
    run(['systemctl', 'disable', OWNER_HY2], False)
    for entry in reversed(journal['entries']):
        path = managed_destination(entry['path'])
        actual = observation(path).get('sha256')
        require(actual in (entry['before_sha256'], entry['after_sha256']), 'Concurrent edit during rollback')
        if actual == entry['before_sha256']:
            continue
        if entry['before_sha256'] is None:
            path.unlink()
        else:
            atomic(path, safe(stage / entry['backup'], True).read_bytes(), entry['before_attributes'])
    bytecode(journal['entries'])
    for directory in reversed(journal['directories']):
        path = safe(directory)
        require(path.is_dir(), 'Rollback directory type changed')
        if not any(path.iterdir()):
            path.rmdir()
        else:
            require(path == SYSTEMD / (PANEL + '.d'), 'Concurrent contents prevent directory removal')
    original = journal['data_attributes']
    os.chown(str(DATA), original['uid'], original['gid'])
    os.chmod(str(DATA), original['mode'])
    run(['systemctl', 'daemon-reload'])
    run(['/usr/local/bin/caddy', 'validate', '--config', str(CADDY_CONFIG), '--adapter', 'caddyfile'])
    run(['systemctl', 'reload', 'caddy.service'])
    run(['systemctl', 'enable', LEGACY])
    for name in ('xray.service', LEGACY, PANEL):
        run(['systemctl', 'start', name])
    wait_panel(journal['configuration']['origin'])
    compare_protected(journal['before'], protected_snapshot(), rollback=True)
    require(not baseline_check(journal['configuration']), 'Restored source baseline differs')
    journal['phase'] = 'rolled-back'
    write_json(stage / 'transaction.private.json', journal)


def main():
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True)
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    require(os.name == 'posix' and os.geteuid() == 0 and sys.version_info[:2] == (3, 6),
            'Root host Python 3.6 required')
    os.umask(0o077)
    stage = safe(args.stage)
    require(stage.parent == Path('/root') and re.fullmatch(r'vps-console-adoption-[A-Za-z0-9_-]+', stage.name)
            and stage.is_dir() and stage.stat().st_uid == 0 and stat.S_IMODE(stage.stat().st_mode) == 0o700,
            'Unsafe deployment stage')
    require(not LOCK.is_symlink(), 'Unsafe maintenance lock')
    descriptor = os.open(str(LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result = {'success': False, 'phase': 'preflight', 'stage': str(stage), 'production_updated': False}
    journal, stopped = None, False
    try:
        configuration = json.load(sys.stdin)
        require(sha(safe(stage / 'deploy_remote.py', True).read_bytes()) == configuration['helper_sha256'],
                'Remote helper changed')
        if args.rollback:
            journal = json.loads(safe(stage / 'transaction.private.json', True).read_text(encoding='utf-8'))
            require(all(configuration.get(key) == journal.get('configuration', {}).get(key) for key in (
                'deployment_ip', 'origin', 'baseline_sha256', 'release_sha256', 'release_files',
                'vendor_sha256', 'vendor_files', 'archive_sha256', 'certificate_sha256', 'hy2_sni')),
                'Reviewed release differs from the retained rollback transaction')
            configuration.update(journal['configuration'])
            if service(PANEL)['ActiveState'] == 'active':
                login_idle(configuration, migrated=True)
            rollback(stage, journal)
            result.update(success=True, phase='manual-rollback-complete', rollback_success=True)
            return result
        require(configuration.get('format') == SOURCE_FORMAT
                and re.fullmatch(r'[0-9.]+', configuration.get('deployment_ip', ''))
                and configuration.get('origin') == 'https://' + configuration['deployment_ip'].replace('.', '-') + '.sslip.io:8443'
                and configuration.get('hy2_sni') == 'raksmart-hy2.local', 'Unexpected frozen host target')
        require(sha(safe(stage / 'deploy_remote.py', True).read_bytes()) == configuration['helper_sha256'],
                'Remote helper changed')
        require(configuration['migration_assets_sha256'] == {name: sha(value.encode('utf-8')) for name, value in ASSETS.items()},
                'Migration service assets differ')
        sources, vendors, candidate = unpack(stage, configuration)
        drift = baseline_check(configuration)
        if drift:
            result.update(phase='baseline-drift', drift=drift)
            return result
        launch_context(configuration)
        login_idle(configuration)
        before_ledger = first_adoption_preflight(configuration)
        before = protected_snapshot()
        write_json(stage / 'protected-before.private.json', before)
        migration, old_state = migration_payloads(configuration, candidate)
        original_caddy = safe(CADDY_CONFIG, True).read_bytes()
        candidate_caddy = caddy_backup_limit(original_caddy)
        atomic(stage / 'Caddyfile.candidate', candidate_caddy)
        run(['/usr/local/bin/caddy', 'validate', '--config', str(stage / 'Caddyfile.candidate'),
             '--adapter', 'caddyfile'])
        migration[str(CADDY_CONFIG)] = (candidate_caddy, info(CADDY_CONFIG))
        payloads = {str(APP / name): (value, info(APP / name) if (APP / name).exists() else default_info())
                    for name, value in dict(sources, **vendors).items()}
        payloads.update(migration)
        payloads.update({name: (value.encode('utf-8'), default_info()) for name, value in ASSETS.items()})
        # A concrete instance filename is required by systemd 219 verification.
        for name, text in (('xray-panel@0123456789abcdef.service', XRAY_TEMPLATE),
                           ('raksmart-hy2@443.service', HY2_TEMPLATE)):
            atomic(stage / name, text.encode('utf-8'), default_info())
            run(['systemd-analyze', 'verify', str(stage / name)])
        journal = checkpoint(stage, payloads, configuration, before, old_state)
        result['changed_files'] = len(journal['entries'])
        result['phase'] = 'stop-panel'
        login_idle(configuration)
        stopped = True
        run(['systemctl', 'stop', PANEL])
        require(service(PANEL)['ActiveState'] == 'inactive', 'Panel did not stop')
        require(not baseline_check(configuration), 'Source baseline changed after stopping panel')
        require(protected_snapshot()['files'] == before['files'], 'Protected bytes changed before installation')
        # Recheck every transactional original before the first host write.
        validate_rollback(stage, journal)
        journal['phase'] = 'installing'
        write_json(stage / 'transaction.private.json', journal)
        ensure_parents(stage, journal, MEMBERS / 'reserved')
        for entry in journal['entries']:
            path = managed_destination(entry['path'])
            ensure_parents(stage, journal, path)
            require(observation(path).get('sha256') == entry['before_sha256'], 'Concurrent edit before replacement')
            atomic(path, payloads[entry['path']][0], entry['after_attributes'])
        result['bytecode_removed'] = bytecode(journal['entries'])
        os.chown(str(DATA), 0, grp.getgrnam('hy2').gr_gid)
        os.chmod(str(DATA), 0o710)
        result['phase'] = 'proxy-migration'
        run(['systemctl', 'stop', LEGACY])
        run(['systemctl', 'disable', LEGACY])
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'reload', 'caddy.service'])
        run(['systemctl', 'restart', 'xray.service'])
        run(['systemctl', 'enable', OWNER_HY2])
        run(['systemctl', 'start', OWNER_HY2])
        wait_proxies()
        journal['phase'] = 'starting'
        write_json(stage / 'transaction.private.json', journal)
        result['phase'] = 'start-panel'
        run(['systemctl', 'start', PANEL])
        wait_panel(configuration['origin'])
        login_idle(configuration, migrated=True)
        verify_installed(stage, journal, old_state, before_ledger)
        configuration['credentials'].clear()
        journal['phase'] = 'complete'
        write_json(stage / 'transaction.private.json', journal)
        result.update(success=True, phase='complete', production_updated=True,
                      original_proxy_identities_preserved=True, original_hy2_password_and_tls_preserved=True,
                      applied_exits_rules_drafts_history_preserved=True, caddy_epoch_preserved=True,
                      firewall_and_network_preserved=True, traffic_cumulative_non_decreasing=True,
                      member_count=0, default_member_ports=[1443, 2443],
                      hy2_follows_web_exit=True, public_member_ingress_verification='not_checked',
                      archive_sha256=configuration['archive_sha256'],
                      migration_assets_sha256=configuration['migration_assets_sha256'])
        result.update(backup_preview_body_limit_bytes=48000000, other_requests_body_limit_bytes=64000,
                      caddy_before_sha256=sha(original_caddy), caddy_after_sha256=sha(candidate_caddy),
                      caddy_reloaded=True, caddy_restarted=False,
                      backup_key_traffic_audit_preserved_on_rollback=True)
        result['global_ipv6_address_present'] = configuration['global_ipv6_address_present']
    except BaseException as error:
        result.update(error_type=type(error).__name__,
                      failure=str(error) if isinstance(error, RuntimeError) else 'Adoption transaction failed')
        if stopped and journal is not None and not args.rollback:
            try:
                rollback(stage, journal)
                result['rollback_success'] = True
            except BaseException as rollback_error:
                result.update(rollback_success=False, rollback_incomplete=True,
                              rollback_error_type=type(rollback_error).__name__)
        elif stopped:
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
        result = {'success': False, 'error_type': type(error).__name__,
                  'failure': 'Adoption stopped before transaction initialization'}
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result.get('success') else 1)
