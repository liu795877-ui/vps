"""Install a fresh console; adopt the inspected node without changing its config."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
from urllib.request import urlopen

STAGE = Path('/root/raksmart-proxy-deploy-20261009/panel')
SOURCE = STAGE / 'release'
TARGET = Path('/opt/vps-panel')
DATA = Path('/var/lib/vps-panel')
ORIGIN = 'https://198-200-49-63.sslip.io:8443'
CONFIG = Path('/usr/local/etc/xray/config.json')
CADDY_BINARY = Path('/root/raksmart-proxy-deploy-20261009/caddy/caddy')
PROTECTED = [CONFIG, Path('/usr/local/etc/raksmart-hy2/server.yaml'),
             Path('/etc/systemd/system/xray.service'),
             Path('/etc/systemd/system/raksmart-hy2.service'), Path('/etc/resolv.conf')]
CREATED_SERVICES = []
STATE = {'phase': 'starting', 'status': 'running', 'created_paths': [],
         'created_services': CREATED_SERVICES, 'origin': ORIGIN,
         'protected_hashes': {}, 'started_at': time.time()}


def record(phase, status='running', **values):
    STATE.update(values)
    STATE.update(phase=phase, status=status, updated_at=time.time())
    temporary = STAGE / '.install-state.tmp'
    temporary.write_text(json.dumps(STATE, indent=2), encoding='utf-8')
    os.chmod(str(temporary), 0o600)
    os.replace(str(temporary), str(STAGE / 'install-state.json'))
    with (STAGE / 'install-events.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'phase': phase, 'status': status, 'at': STATE['updated_at']}) + '\n')


def created(path):
    STATE['created_paths'].append(str(path))
    record(STATE['phase'])


def run(args, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        (STAGE / 'last-command.private.log').write_bytes(result.stdout + b'\n' + result.stderr)
        raise RuntimeError('Command failed during ' + STATE['phase'] + ': ' + Path(args[0]).name)
    return result.stdout.decode('utf-8', errors='replace').strip()


def wait_service(service, port):
    for attempt in range(40):
        result = subprocess.run(['systemctl', 'is-active', '--quiet', service])
        if result.returncode == 0:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    return
            except OSError:
                pass
        time.sleep(.2)
    raise RuntimeError('Service did not start: ' + service)


def hashes():
    return {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in PROTECTED}


def install():
    record('preflight')
    if os.geteuid() != 0 or sys.version_info < (3, 6):
        raise RuntimeError('Root and Python 3.6 or newer are required')
    for path in [TARGET, DATA, Path('/usr/local/bin/caddy'), Path('/etc/caddy'),
                 Path('/var/lib/caddy'), Path('/etc/systemd/system/caddy.service'),
                 Path('/etc/systemd/system/vps-panel.service')]:
        if path.exists() or path.is_symlink():
            raise RuntimeError('Installation destination already exists: ' + str(path) + '; inspect any previous install-state.json')
    for tool in ['systemctl', 'install', 'getent', 'useradd', 'setcap', 'runuser', 'curl']:
        if not shutil.which(tool):
            raise RuntimeError('Missing required tool: ' + tool)
    if subprocess.run(['getent', 'passwd', 'caddy'], stdout=subprocess.PIPE).returncode == 0:
        raise RuntimeError('An existing caddy user requires review')
    if subprocess.run(['getent', 'group', 'caddy'], stdout=subprocess.PIPE).returncode == 0:
        raise RuntimeError('An existing caddy group requires review')
    for service in ['xray.service', 'raksmart-hy2.service']:
        run(['systemctl', 'is-active', '--quiet', service])
        run(['systemctl', 'is-enabled', '--quiet', service])
    for port in [80, 8443, 18787]:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1' if port == 18787 else '0.0.0.0', port))
    for path in [SOURCE / 'panel/server.py', STAGE / 'auth-seed.private.json',
                 STAGE / 'base.private.yaml', STAGE / 'Caddyfile', STAGE / 'caddy.service',
                 STAGE / 'release-manifest.json', CADDY_BINARY,
                 CADDY_BINARY.parent / 'verification.json']:
        if not path.is_file() or path.is_symlink():
            raise RuntimeError('Missing or unsafe installation input: ' + str(path))
    if CONFIG.is_symlink():
        raise RuntimeError('Refusing to adopt a symlink Xray configuration')
    original_hashes = hashes()
    manifest = json.loads((STAGE / 'release-manifest.json').read_text(encoding='utf-8'))
    if original_hashes[str(CONFIG)] != manifest['adoption_config_sha256']:
        raise RuntimeError('The inspected Xray configuration changed; restage adoption inputs')
    verification = json.loads((CADDY_BINARY.parent / 'verification.json').read_text(encoding='utf-8'))
    if hashlib.sha256(CADDY_BINARY.read_bytes()).hexdigest() != verification['binary_sha256']:
        raise RuntimeError('Verified Caddy binary changed')
    run([str(CADDY_BINARY), 'version'])
    sys.path.insert(0, str(SOURCE))
    import configure_static_exits as static
    static.inspect_base(json.loads(CONFIG.read_text(encoding='utf-8')),
                        (STAGE / 'base.private.yaml').read_text(encoding='utf-8'), '198.200.49.63')
    auth = json.loads((STAGE / 'auth-seed.private.json').read_text(encoding='utf-8'))
    if auth.get('username') != 'admin' or auth.get('iterations', 0) < 600000:
        raise RuntimeError('Invalid independent authentication seed')
    record('linux-tests', protected_hashes=original_hashes)
    environment = os.environ.copy()
    environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
    tests = subprocess.run([sys.executable, '-m', 'unittest', 'test_configure_reality',
                            'test_configure_static_exits', 'panel.test_panel'], cwd=str(SOURCE),
                           env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=150)
    (STAGE / 'linux-tests.private.log').write_bytes(tests.stdout + b'\n' + tests.stderr)
    if tests.returncode:
        raise RuntimeError('Linux application/core tests failed before installation')

    record('copy-application')
    created(TARGET)
    shutil.copytree(str(SOURCE), str(TARGET))
    for path in TARGET.rglob('*'):
        os.chmod(str(path), 0o755 if path.is_dir() else 0o644)
    os.chmod(str(TARGET), 0o755)
    created(DATA)
    DATA.mkdir(mode=0o700)
    for source, destination in [('auth-seed.private.json', 'auth.private.json'),
                                ('base.private.yaml', 'base.private.yaml')]:
        shutil.copyfile(str(STAGE / source), str(DATA / destination))
        os.chmod(str(DATA / destination), 0o600)
    record('adopt-existing-node')
    from panel.server import Manager
    Manager(DATA, '198.200.49.63', CONFIG, DATA / 'base.private.yaml', origin=ORIGIN)
    if hashes() != original_hashes:
        raise RuntimeError('Node adoption changed a protected configuration')
    unit = '''# Managed by Private Node Console; systemd219 compatible
[Unit]
Description=Private static IP exit console
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-panel
ExecStart=/usr/bin/python3 /opt/vps-panel/panel/server.py --directory /var/lib/vps-panel --public-ip 198.200.49.63 --origin https://198-200-49-63.sslip.io:8443 --port 18787
Restart=on-failure
RestartSec=2
UMask=0077
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=true
ReadOnlyDirectories=/opt/vps-panel
ReadWriteDirectories=/var/lib/vps-panel /usr/local/etc/xray
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_NET_BIND_SERVICE
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
'''
    record('start-backend')
    created('/etc/systemd/system/vps-panel.service')
    Path('/etc/systemd/system/vps-panel.service').write_text(unit, encoding='utf-8')
    os.chmod('/etc/systemd/system/vps-panel.service', 0o644)
    CREATED_SERVICES.append('vps-panel.service')
    record('start-backend')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', 'vps-panel.service'])
    wait_service('vps-panel.service', 18787)
    with urlopen('http://127.0.0.1:18787/api/session', timeout=3) as response:
        if json.loads(response.read().decode())['authenticated']:
            raise RuntimeError('Unauthenticated session check failed')

    record('install-https')
    STATE['created_caddy_user'] = True
    record('install-https')
    run(['useradd', '--system', '--user-group', '--home-dir', '/var/lib/caddy', '--no-create-home', '--shell', '/sbin/nologin', 'caddy'])
    created('/usr/local/bin/caddy')
    run(['install', '-m', '0755', str(CADDY_BINARY), '/usr/local/bin/caddy'])
    run(['setcap', 'cap_net_bind_service=ep', '/usr/local/bin/caddy'])
    created('/etc/caddy')
    run(['install', '-d', '-m', '0750', '-o', 'root', '-g', 'caddy', '/etc/caddy'])
    created('/var/lib/caddy')
    run(['install', '-d', '-m', '0750', '-o', 'caddy', '-g', 'caddy', '/var/lib/caddy'])
    run(['install', '-m', '0640', '-o', 'root', '-g', 'caddy', str(STAGE / 'Caddyfile'), '/etc/caddy/Caddyfile'])
    created('/etc/systemd/system/caddy.service')
    run(['install', '-m', '0644', str(STAGE / 'caddy.service'), '/etc/systemd/system/caddy.service'])
    run(['runuser', '-u', 'caddy', '--', '/usr/local/bin/caddy', 'validate', '--config', '/etc/caddy/Caddyfile', '--adapter', 'caddyfile'])
    record('start-https')
    CREATED_SERVICES.append('caddy.service')
    record('start-https')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'start', 'caddy.service'])
    wait_service('caddy.service', 8443)
    record('verify-and-enable')
    for service in CREATED_SERVICES:
        run(['systemctl', 'enable', service])
    for service in ['xray.service', 'raksmart-hy2.service']:
        run(['systemctl', 'is-active', '--quiet', service])
        run(['systemctl', 'is-enabled', '--quiet', service])
    if hashes() != original_hashes:
        raise RuntimeError('Protected configurations changed during installation')
    result = {'installed': True, 'origin': ORIGIN, 'services': list(CREATED_SERVICES),
              'base_config_preserved': True, 'hy2_config_preserved': True,
              'dns_preserved': True, 'initial_exit_count': 0,
              'backend_listen': '127.0.0.1:18787', 'external_https_verification_pending': True}
    record('complete', 'complete', result=result)
    print(json.dumps(result))


def interrupted(signum, frame):
    raise KeyboardInterrupt('Installation interrupted by signal ' + str(signum))


def main():
    os.umask(0o077)
    with (STAGE / 'install.lock').open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        try:
            install()
        except BaseException as error:
            failed_phase = STATE['phase']
            for service in reversed(CREATED_SERVICES):
                subprocess.run(['systemctl', 'disable', '--now', service], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            preserved = None
            if STATE['protected_hashes']:
                try:
                    preserved = hashes() == STATE['protected_hashes']
                except OSError:
                    preserved = False
            record(failed_phase, 'interrupted' if isinstance(error, KeyboardInterrupt) else 'failed',
                   error_type=type(error).__name__, error=str(error), protected_configs_preserved=preserved,
                   review_required=True, created_services_stopped=True)
            (STAGE / 'install-error.private.log').write_text(traceback.format_exc(), encoding='utf-8')
            print('Installation stopped at ' + failed_phase + '; inspect ' + str(STAGE / 'install-state.json'), file=sys.stderr)
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
