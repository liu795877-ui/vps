"""Reviewed VPS-side HY2 installation/rollback helper; never runs on import.

The publisher stages this file, manifest.json and JSON-formatted PORT.yaml
files in a private directory. JSON is valid YAML and avoids a server PyYAML
dependency. Only an explicit install command changes the host. No credential
or configuration content is printed, including on failure.
"""
import argparse
from datetime import datetime
import grp
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import time


PORTS = (443, 1443, 2443)
BINARY = Path('/usr/local/bin/raksmart-hysteria2')
BINARY_SHA256 = '907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691'
CERTIFICATE_SHA256 = '719524027ace548d1251736cb2a2f603572d380e2237f8bdf8d3a3913af2b597'
DIRECTORY = Path('/usr/local/etc/raksmart-hy2')
ACCOUNTS = DIRECTORY / 'accounts'
CERTIFICATE = DIRECTORY / 'server.crt.pem'
PRIVATE_KEY = DIRECTORY / 'server.key.pem'
PANEL_DIRECTORY = Path('/var/lib/vps-panel')
ACCOUNT_CERTIFICATE = PANEL_DIRECTORY / 'hy2-server.crt.pem'
ACCOUNT_PRIVATE_KEY = PANEL_DIRECTORY / 'hy2-server.key.pem'
LEGACY_CONFIG = DIRECTORY / 'server.yaml'
LEGACY_SERVICE = 'raksmart-hy2.service'
TEMPLATE_PATH = Path('/etc/systemd/system/raksmart-hy2@.service')

SYSTEMD_TEMPLATE = '''[Unit]
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


def service(port):
    if port not in PORTS:
        raise ValueError('Unsupported instance port')
    return 'raksmart-hy2@{}.service'.format(port)


def run(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=20)
    if check and result.returncode:
        raise RuntimeError('Host command failed')
    return result


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def cert_pin():
    certificate = run(['openssl', 'x509', '-in', str(CERTIFICATE), '-outform', 'DER'])
    return hashlib.sha256(certificate.stdout).hexdigest()


def state(name):
    return {'active': run(['systemctl', 'is-active', '--quiet', name], False).returncode == 0,
            'enabled': run(['systemctl', 'is-enabled', '--quiet', name], False).returncode == 0}


def inspect():
    version = run([str(BINARY), 'version']).stdout.decode('utf-8', 'replace')
    digest = sha256(BINARY)
    pin = cert_pin()
    if digest != BINARY_SHA256 or 'Version:\tv2.13.0' not in version:
        raise RuntimeError('Official binary differs from the reviewed release')
    if pin != CERTIFICATE_SHA256:
        raise RuntimeError('The existing certificate pin changed')
    if not PRIVATE_KEY.is_file():
        raise RuntimeError('Existing private key is missing')
    group = grp.getgrnam('hy2')
    capability = run(['getcap', str(BINARY)]).stdout.decode('ascii', 'replace')
    if 'cap_net_bind_service' not in capability:
        raise RuntimeError('Reviewed low-port capability is missing')
    return {'binary_sha256': digest, 'certificate_sha256': pin,
            'version': 'v2.13.0', 'hy2_gid': group.gr_gid,
            'legacy': state(LEGACY_SERVICE),
            'instances': {str(port): state(service(port)) for port in PORTS}}


def verify_certificate_copies():
    if (ACCOUNT_CERTIFICATE.read_bytes() != CERTIFICATE.read_bytes()
            or ACCOUNT_PRIVATE_KEY.read_bytes() != PRIVATE_KEY.read_bytes()):
        raise RuntimeError('Backup-owned TLS copies differ from the original identity')
    for path in (ACCOUNT_CERTIFICATE, ACCOUNT_PRIVATE_KEY):
        if path.is_symlink():
            raise RuntimeError('TLS copy must be a regular private file')
    return True


def parse_config(data, port):
    config = json.loads(data.decode('utf-8'))
    expected_stats = '127.0.0.1:{}'.format(18600 + port)
    expected_socks = '127.0.0.1:{}'.format(15600 + port)
    if (config.get('listen') != '0.0.0.0:{}'.format(port)
            or config.get('tls') != {'cert': str(ACCOUNT_CERTIFICATE), 'key': str(ACCOUNT_PRIVATE_KEY)}
            or config.get('disableUDP') is not True
            or config.get('ignoreClientBandwidth') is not True):
        raise ValueError('Unexpected account instance configuration')
    auth = config.get('auth', {})
    statistics = config.get('trafficStats', {})
    if (auth.get('type') != 'password' or not isinstance(auth.get('password'), str)
            or len(auth['password']) < 24 or statistics.get('listen') != expected_stats
            or not isinstance(statistics.get('secret'), str) or len(statistics['secret']) < 24):
        raise ValueError('Invalid private account credentials or statistics endpoint')
    outbound = config.get('outbounds', [])
    if len(outbound) != 1 or outbound[0].get('type') != 'socks5':
        raise ValueError('Account instance must use its private SOCKS entrance')
    socks = outbound[0].get('socks5', {})
    if (socks.get('addr') != expected_socks or not isinstance(socks.get('username'), str)
            or not socks['username'] or not isinstance(socks.get('password'), str)
            or len(socks['password']) < 24):
        raise ValueError('Invalid account SOCKS entrance')
    # SOCKS domain addresses stay intact; its account Xray owns target DNS/routing.
    if config.get('resolver', {}).get('type', 'system') not in ('', 'system'):
        raise ValueError('Unexpected resolver in account instance')
    return config


def load_stage(stage):
    stage = Path(stage).resolve()
    manifest = json.loads((stage / 'manifest.json').read_text(encoding='utf-8'))
    if (manifest.get('version') != 1 or manifest.get('binary_sha256') != BINARY_SHA256
            or manifest.get('certificate_sha256') != CERTIFICATE_SHA256):
        raise ValueError('Unreviewed integration stage')
    entries = manifest.get('instances', [])
    if not 1 <= len(entries) <= 3:
        raise ValueError('Invalid number of account instances')
    configs = {}
    for entry in entries:
        port = entry.get('port')
        if type(port) is not int or port not in PORTS or port in configs:
            raise ValueError('Invalid instance identity')
        filename = entry.get('config', '{}.yaml'.format(port))
        if filename != '{}.yaml'.format(port) or type(entry.get('enabled')) is not bool:
            raise ValueError('Invalid instance file or lifecycle flag')
        path = stage / filename
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry.get('sha256'):
            raise ValueError('Staged instance checksum differs')
        configs[port] = {'data': data, 'config': parse_config(data, port),
                         'enabled': entry['enabled']}
    if 443 not in configs or not configs[443]['enabled']:
        raise ValueError('The administrator instance must remain available')
    passwords = [item['config']['auth']['password'] for item in configs.values()]
    if len(set(passwords)) != len(passwords):
        raise ValueError('Account proxy passwords must be independent')
    return configs


def atomic_file(path, data, mode, uid, gid):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '.hy2-integration-' + str(os.getpid()))
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(str(temporary), uid, gid)
        os.chmod(str(temporary), mode)
        os.replace(str(temporary), str(path))
    finally:
        if temporary.exists():
            temporary.unlink()


def managed_files():
    return [TEMPLATE_PATH, LEGACY_CONFIG, ACCOUNT_CERTIFICATE, ACCOUNT_PRIVATE_KEY] + [
        ACCOUNTS / '{}.yaml'.format(port) for port in PORTS]


def receive_exact(stream, length):
    data = b''
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise RuntimeError('Private account SOCKS connection closed')
        data += chunk
    return data


def snapshot(destination):
    destination = Path(destination).resolve()
    if destination.parent != Path('/root') or not destination.name.startswith('hy2-integration-backup-'):
        raise ValueError('Rollback snapshot must use a dedicated root directory')
    destination.mkdir(mode=0o700, exist_ok=False)
    metadata = {'version': 1, 'files': [], 'services': {}, 'directories': [],
                'binary_sha256': sha256(BINARY), 'certificate_sha256': cert_pin()}
    for index, path in enumerate(managed_files()):
        if path.is_symlink():
            raise ValueError('Refusing to replace a linked managed file')
        entry = {'path': str(path), 'exists': path.exists(), 'backup': str(index)}
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Managed path is not a regular file')
            entry.update(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
            target = destination / str(index)
            target.write_bytes(path.read_bytes())
            target.chmod(0o600)
            entry['sha256'] = sha256(target)
        metadata['files'].append(entry)
    for name in [LEGACY_SERVICE] + [service(port) for port in PORTS]:
        metadata['services'][name] = state(name)
    for path in (PANEL_DIRECTORY, ACCOUNTS):
        info = path.stat() if path.exists() else None
        metadata['directories'].append({'path': str(path), 'exists': info is not None,
            'mode': stat.S_IMODE(info.st_mode) if info else None,
            'uid': info.st_uid if info else None, 'gid': info.st_gid if info else None})
    atomic_file(destination / 'snapshot.json', (json.dumps(metadata, indent=2) + '\n').encode(),
                0o600, 0, 0)
    return destination


def rollback(destination):
    destination = Path(destination).resolve()
    if destination.parent != Path('/root') or not destination.name.startswith('hy2-integration-backup-'):
        raise ValueError('Invalid rollback snapshot directory')
    metadata = json.loads((destination / 'snapshot.json').read_text(encoding='utf-8'))
    allowed = {str(path) for path in managed_files()}
    entries = metadata.get('files', [])
    if metadata.get('version') != 1 or {item['path'] for item in entries} != allowed:
        raise ValueError('Invalid rollback file inventory')
    if metadata.get('binary_sha256') != sha256(BINARY) or metadata.get('certificate_sha256') != cert_pin():
        raise ValueError('Binary or certificate changed after snapshot')
    for index, entry in enumerate(entries):
        if entry['backup'] != str(index) or Path(entry['path']).is_symlink():
            raise ValueError('Invalid rollback file')
        if entry['exists'] and sha256(destination / str(index)) != entry.get('sha256'):
            raise ValueError('Rollback file checksum differs')
    for name in [LEGACY_SERVICE] + [service(port) for port in PORTS]:
        run(['systemctl', 'stop', name], False)
        run(['systemctl', 'disable', name], False)
    for index, entry in enumerate(entries):
        path = Path(entry['path'])
        if entry['backup'] != str(index) or path.is_symlink():
            raise ValueError('Invalid rollback file')
        if entry['exists']:
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_file(path, (destination / str(index)).read_bytes(), entry['mode'], entry['uid'], entry['gid'])
        elif path.exists():
            path.unlink()
    run(['systemctl', 'daemon-reload'])
    for entry in metadata.get('directories', []):
        if entry['path'] not in (str(PANEL_DIRECTORY), str(ACCOUNTS)):
            raise ValueError('Invalid rollback directory')
        path = Path(entry['path'])
        if entry['exists']:
            os.chown(str(path), entry['uid'], entry['gid'])
            os.chmod(str(path), entry['mode'])
        elif path.is_dir():
            # Remove only an empty directory introduced by this installation.
            try:
                path.rmdir()
            except OSError:
                pass
    for name, previous in metadata['services'].items():
        if name not in [LEGACY_SERVICE] + [service(port) for port in PORTS]:
            raise ValueError('Invalid rollback service')
        if previous['enabled']:
            run(['systemctl', 'enable', name])
        if previous['active']:
            run(['systemctl', 'start', name])
    return {'rolled_back': True, 'snapshot': str(destination), 'certificate_sha256': cert_pin()}


def wait_ready(port, config):
    import urllib.request
    for unused in range(20):
        if state(service(port))['active']:
            request = urllib.request.Request('http://127.0.0.1:{}/traffic'.format(18600 + port),
                                             headers={'Authorization': config['trafficStats']['secret']})
            try:
                with urllib.request.urlopen(request, timeout=1) as response:
                    payload = json.loads(response.read().decode('utf-8'))
                if isinstance(payload, dict):
                    return
            except Exception:
                pass
        time.sleep(0.25)
    raise RuntimeError('Account HY2 statistics did not become ready')


def install(stage, backup):
    if os.geteuid() != 0:
        raise RuntimeError('Installation requires the root deployment process')
    baseline = inspect()
    configs = load_stage(stage)
    # Every desired account Xray must already have its private listener before
    # the legacy UDP443 service is stopped. This detects deployment-order errors.
    for port, entry in configs.items():
        if entry['enabled']:
            with socket.create_connection(('127.0.0.1', 15600 + port), timeout=2) as stream:
                stream.sendall(b'\x05\x01\x02')
                if receive_exact(stream, 2) != b'\x05\x02':
                    raise RuntimeError('Private account SOCKS authentication is not ready')
                socks = entry['config']['outbounds'][0]['socks5']
                username, password = socks['username'].encode('utf-8'), socks['password'].encode('utf-8')
                if not 1 <= len(username) <= 255 or not 1 <= len(password) <= 255:
                    raise ValueError('Invalid SOCKS credential length')
                stream.sendall(b'\x01' + bytes([len(username)]) + username
                               + bytes([len(password)]) + password)
                if receive_exact(stream, 2) != b'\x01\x00':
                    raise RuntimeError('Private account SOCKS credentials are not ready')
    destination = snapshot(backup)
    try:
        if PANEL_DIRECTORY.is_symlink() or ACCOUNTS.is_symlink():
            raise ValueError('Managed directories must not be linked')
        PANEL_DIRECTORY.mkdir(parents=True, exist_ok=True)
        # hy2 may traverse this directory; existing panel private files remain
        # root-only. CentOS 7 systemd lacks the modern credential-file facility.
        os.chown(str(PANEL_DIRECTORY), 0, baseline['hy2_gid'])
        PANEL_DIRECTORY.chmod(0o710)
        for destination_path, original, mode in (
                (ACCOUNT_CERTIFICATE, CERTIFICATE, 0o640),
                (ACCOUNT_PRIVATE_KEY, PRIVATE_KEY, 0o640)):
            if destination_path.exists() and destination_path.read_bytes() != original.read_bytes():
                raise ValueError('An existing backup-owned TLS identity differs')
            atomic_file(destination_path, original.read_bytes(), mode, 0, baseline['hy2_gid'])
        verify_certificate_copies()
        ACCOUNTS.mkdir(parents=True, exist_ok=True)
        os.chown(str(ACCOUNTS), 0, baseline['hy2_gid'])
        ACCOUNTS.chmod(0o750)
        for port, entry in configs.items():
            atomic_file(ACCOUNTS / '{}.yaml'.format(port), entry['data'], 0o640, 0, baseline['hy2_gid'])
        atomic_file(TEMPLATE_PATH, SYSTEMD_TEMPLATE.encode(), 0o644, 0, 0)
        run(['systemctl', 'stop', LEGACY_SERVICE])
        run(['systemctl', 'disable', LEGACY_SERVICE])
        # Retire the old single-password path. A manual legacy-service start
        # cannot restore an unmetered ingress; rollback alone restores this file.
        if LEGACY_CONFIG.exists():
            LEGACY_CONFIG.unlink()
        run(['systemctl', 'daemon-reload'])
        for port in PORTS:
            entry = configs.get(port)
            if entry and entry['enabled']:
                run(['systemctl', 'enable', service(port)])
                run(['systemctl', 'restart', service(port)])
                wait_ready(port, entry['config'])
            else:
                run(['systemctl', 'stop', service(port)], False)
                run(['systemctl', 'disable', service(port)], False)
        if state(LEGACY_SERVICE)['active'] or LEGACY_CONFIG.exists() or cert_pin() != CERTIFICATE_SHA256:
            raise RuntimeError('Legacy retirement or certificate preservation failed')
        return {'installed': True, 'ports': sorted(configs), 'snapshot': str(destination),
                'binary_sha256': BINARY_SHA256, 'certificate_sha256': CERTIFICATE_SHA256,
                'legacy_revoked': True}
    except Exception:
        rollback(destination)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('inspect', 'install', 'rollback'))
    parser.add_argument('--stage')
    parser.add_argument('--snapshot')
    args = parser.parse_args()
    try:
        if args.operation == 'inspect':
            result = inspect()
        elif args.operation == 'install':
            if not args.stage:
                parser.error('install requires --stage')
            backup = args.snapshot or '/root/hy2-integration-backup-' + datetime.utcnow().strftime('%Y%m%dT%H%M%S')
            result = install(args.stage, backup)
        else:
            if not args.snapshot:
                parser.error('rollback requires --snapshot')
            result = rollback(args.snapshot)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        # Deliberately omit exception text and remote stderr: config parsers or
        # commands can include private inputs. The publisher owns private logs.
        print(json.dumps({'success': False, 'operation': args.operation,
                          'error_type': type(error).__name__}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
