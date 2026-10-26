"""Install the prepared CentOS-compatible panel and independent Caddy site."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

STAGE = Path('/root/raksmart-proxy-deploy-20261009/panel')
TARGET = Path('/opt/vps-panel')
DATA = Path('/var/lib/vps-panel')
ORIGIN = 'https://198-200-49-158.sslip.io:8443'
CONFIG = Path('/usr/local/etc/xray/config.json')
SOURCE = STAGE / 'release'
CREATED_SERVICES = []

def run(args, timeout=30):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        (STAGE/'last-command.private.log').write_bytes(result.stdout+b'\n'+result.stderr)
        raise RuntimeError('Command failed: ' + Path(args[0]).name)
    return result.stdout.decode('utf-8', errors='replace').strip()

def wait_service(service, port):
    for _ in range(30):
        result = subprocess.run(['systemctl','is-active','--quiet',service])
        if result.returncode == 0:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):
                    return
            except OSError:
                pass
        time.sleep(.2)
    raise RuntimeError('Service did not start: ' + service)

def install():
    if os.geteuid() != 0:
        raise RuntimeError('Root installation required')
    for path in [TARGET, DATA, Path('/usr/local/bin/caddy'), Path('/etc/caddy'),
                 Path('/etc/systemd/system/caddy.service'), Path('/etc/systemd/system/vps-panel.service')]:
        if path.exists() or path.is_symlink():
            raise RuntimeError('Deployment destination already exists: ' + str(path))
    for port in [80,8443,18787]:
        with socket.socket() as probe:
            probe.bind(('0.0.0.0' if port != 18787 else '127.0.0.1',port))
    original_hash = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    environment = os.environ.copy()
    environment['XRAY_TEST_BINARY'] = '/usr/local/bin/xray'
    tests = subprocess.run([sys.executable,'-m','unittest','test_configure_reality',
                            'test_configure_static_exits','panel.test_panel'],cwd=str(SOURCE),
                            env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
    (STAGE/'linux-tests.private.log').write_bytes(tests.stdout+b'\n'+tests.stderr)
    if tests.returncode:
        raise RuntimeError('Linux application/core tests failed')
    shutil.copytree(str(SOURCE),str(TARGET))
    for path in TARGET.rglob('*'):
        os.chmod(str(path),0o755 if path.is_dir() else 0o644)
    DATA.mkdir(mode=0o700)
    shutil.copyfile(str(STAGE/'auth-seed.private.json'),str(DATA/'auth.private.json'))
    shutil.copyfile(str(STAGE/'base.private.yaml'),str(DATA/'base.private.yaml'))
    for path in [DATA/'auth.private.json',DATA/'base.private.yaml']:
        os.chmod(str(path),0o600)
    sys.path.insert(0,str(TARGET))
    from panel.server import Manager
    Manager(DATA,'198.200.49.158',CONFIG,DATA/'base.private.yaml',origin=ORIGIN)
    if hashlib.sha256(CONFIG.read_bytes()).hexdigest() != original_hash:
        raise RuntimeError('Panel adoption changed the existing base config')
    unit = '''# Managed by Private Node Console; systemd219 compatible
[Unit]
Description=Private static IP exit console
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vps-panel
ExecStart=/usr/bin/python3 /opt/vps-panel/panel/server.py --directory /var/lib/vps-panel --public-ip 198.200.49.158 --origin https://198-200-49-158.sslip.io:8443 --port 18787
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
    Path('/etc/systemd/system/vps-panel.service').write_text(unit)
    os.chmod('/etc/systemd/system/vps-panel.service',0o644)
    run(['systemctl','daemon-reload'])
    CREATED_SERVICES.append('vps-panel.service')
    run(['systemctl','start','vps-panel.service'])
    wait_service('vps-panel.service',18787)
    with urlopen('http://127.0.0.1:18787/api/session',timeout=3) as response:
        if json.loads(response.read().decode())['authenticated']:
            raise RuntimeError('Unauthenticated session check failed')
    binary = Path('/root/raksmart-proxy-deploy-20261009/caddy/caddy')
    verification = json.loads((binary.parent/'verification.json').read_text())
    if hashlib.sha256(binary.read_bytes()).hexdigest() != verification['binary_sha256']:
        raise RuntimeError('Verified Caddy binary changed')
    if subprocess.run(['getent','passwd','caddy'],stdout=subprocess.PIPE).returncode == 0:
        raise RuntimeError('Existing caddy user needs review')
    run(['useradd','--system','--user-group','--home-dir','/var/lib/caddy','--no-create-home','--shell','/sbin/nologin','caddy'])
    run(['install','-m','0755',str(binary),'/usr/local/bin/caddy'])
    run(['setcap','cap_net_bind_service=ep','/usr/local/bin/caddy'])
    run(['install','-d','-m','0750','-o','root','-g','caddy','/etc/caddy'])
    run(['install','-d','-m','0750','-o','caddy','-g','caddy','/var/lib/caddy'])
    run(['install','-m','0640','-o','root','-g','caddy',str(STAGE/'Caddyfile'),'/etc/caddy/Caddyfile'])
    run(['install','-m','0644',str(STAGE/'caddy.service'),'/etc/systemd/system/caddy.service'])
    run(['runuser','-u','caddy','--','/usr/local/bin/caddy','validate','--config','/etc/caddy/Caddyfile','--adapter','caddyfile'])
    run(['systemctl','daemon-reload'])
    CREATED_SERVICES.append('caddy.service')
    run(['systemctl','start','caddy.service'])
    wait_service('caddy.service',8443)
    for service in CREATED_SERVICES:
        run(['systemctl','enable',service])
    run(['systemctl','is-active','--quiet','xray.service'])
    result = {'installed':True,'origin':ORIGIN,'services':CREATED_SERVICES,
              'base_config_preserved':hashlib.sha256(CONFIG.read_bytes()).hexdigest()==original_hash,
              'backend_listen':'127.0.0.1:18787','external_https_verification_pending':True}
    print(json.dumps(result))

try:
    install()
except Exception:
    for service in reversed(CREATED_SERVICES):
        subprocess.run(['systemctl','stop',service])
    raise
