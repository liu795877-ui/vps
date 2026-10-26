"""Read-only, sanitized production baseline for the .158 adoption."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import sys

import ssh_access as ssh

FOLDER = Path(__file__).resolve().parent
REPORT = FOLDER / 'console-optimization-preflight-20261013.json'
REMOTE = r'''
import hashlib, http.client, json, os, re, stat, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode = True
APP = Path('/opt/vps-panel')
DATA = Path('/var/lib/vps-panel')
def require(value, message):
    if not value: raise RuntimeError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
def read(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Expected regular baseline file')
    return path.read_bytes()
def command(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    return result.returncode, result.stdout.decode('utf-8', 'replace')
def service(name):
    code, output = command(['systemctl', 'show', name, '--no-pager', '--property=LoadState', '--property=ActiveState', '--property=SubState', '--property=UnitFileState', '--property=MainPID', '--property=User', '--property=Group', '--property=FragmentPath'])
    require(code == 0, 'Service observation failed')
    value = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    pid = int(value.get('MainPID', '0'))
    if pid:
        argv = Path('/proc/{}/cmdline'.format(pid)).read_bytes().decode().strip('\0').split('\0')
        require(all(not re.search(r'password|secret|token', item, re.I) for item in argv), 'Unexpected secret-bearing argv')
        value['argv'] = argv
    return value
def file_info(path):
    path = Path(path)
    if not path.exists() and not path.is_symlink(): return {'exists': False}
    require(not path.is_symlink(), 'Baseline contains a symlink')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode), 'Baseline contains a non-file')
    return {'exists': True, 'sha256': sha(path.read_bytes()), 'mode': oct(stat.S_IMODE(info.st_mode)), 'uid': info.st_uid, 'gid': info.st_gid, 'size': info.st_size}
result = {'success': False, 'server': '198.200.49.158', 'ssh_port': 62970,
          'production_updated': False, 'service_control_performed': False, 'secrets_included': False}
phase = 'runtime'
try:
    require(sys.version_info[:2] == (3, 6) and os.geteuid() == 0, 'Unexpected runtime')
    result['python'] = sys.version.split()[0]
    result['services'] = {name: service(name) for name in ['vps-panel.service', 'xray.service', 'raksmart-hy2.service', 'caddy.service']}
    require(all(value.get('ActiveState') == 'active' and value.get('UnitFileState') == 'enabled' for value in result['services'].values()), 'Baseline services differ')
    panel_args = result['services']['vps-panel.service']['argv']
    require('198.200.49.158' in panel_args and 'https://198-200-49-158.sslip.io:8443' in panel_args, 'Panel target differs')
    result['origin'] = 'https://198-200-49-158.sslip.io:8443'
    phase = 'application-source'
    files = []
    for path in APP.rglob('*'):
        relative = path.relative_to(APP).as_posix()
        if 'vendor' in path.relative_to(APP).parts or '__pycache__' in path.relative_to(APP).parts: continue
        if path.is_file() and (path.suffix == '.py' or relative.startswith('panel/web/') or relative in ['panel/services-routing.json', 'panel/smart-routing.json', 'panel/rules/domestic-dns.yaml']):
            files.append((relative, sha(read(path))))
    result['source_sha256'] = dict(sorted(files))
    result['source_file_count'] = len(files)
    result['binary_sha256'] = {str(path): sha(read(path)) for path in ['/usr/local/bin/xray', '/usr/local/bin/raksmart-hysteria2']}
    phase = 'protected-baseline'
    paths = ['/var/lib/vps-panel/auth.private.json', '/var/lib/vps-panel/base.private.yaml', '/var/lib/vps-panel/state.private.json', '/var/lib/vps-panel/node-info.json', '/usr/local/etc/xray/config.json', '/usr/local/etc/raksmart-hy2/server.yaml', '/usr/local/etc/raksmart-hy2/server.crt.pem', '/usr/local/etc/raksmart-hy2/server.key.pem', '/etc/systemd/system/vps-panel.service', '/etc/systemd/system/xray.service', '/etc/systemd/system/raksmart-hy2.service', '/etc/caddy/Caddyfile', '/etc/resolv.conf', '/etc/sysctl.conf', '/etc/sysctl.d/90-vps-hy2-udp-buffers.conf']
    paths += [str(DATA / name) for name in ['users.private.json', 'hy2.private.json', 'traffic.private.json', 'entrance-pool.private.json', 'member-tasks.private.json']]
    result['protected_files'] = {path: file_info(path) for path in paths}
    result['infrastructure_present'] = {path: Path(path).exists() for path in ['/etc/systemd/system/xray-panel@.service', '/etc/systemd/system/raksmart-hy2@.service', '/usr/local/etc/xray-members', '/opt/vps-panel/vendor', '/usr/local/etc/raksmart-hy2/accounts']}
    state = json.loads(read(DATA / 'state.private.json').decode())
    config = json.loads(read('/usr/local/etc/xray/config.json').decode())
    require(state['managed_hash'] == sha(read('/usr/local/etc/xray/config.json')), 'Managed config binding differs')
    result['state'] = {'managed_hash_matches': True, 'field_names': sorted(state), 'exit_count': len(state.get('exits', [])), 'history_count': len(state.get('history', [])), 'active_target': state.get('active_target'), 'routing_mode': state.get('routing_mode'), 'base_sha256': canonical(state.get('base')), 'exit_accounts_sha256': canonical(state.get('exits')), 'history_sha256': canonical(state.get('history')), 'rules_sha256': canonical({key: state.get(key) for key in ['routing_mode', 'domains', 'direct_domains', 'rule_token']}), 'auto_identity_sha256': canonical(state.get('auto_id'))}
    result['xray'] = {'inbound_count': len(config.get('inbounds', [])), 'outbound_count': len(config.get('outbounds', [])), 'reality_inbound_sha256': canonical(config['inbounds'][0]), 'outbounds_sha256': canonical(config.get('outbounds')), 'routing_sha256': canonical(config.get('routing')), 'stats_api_present': 'api' in config}
    phase = 'legacy-hy2-identity'
    legacy = read('/usr/local/etc/raksmart-hy2/server.yaml').decode()
    password_match = re.findall(r'^\s+password:\s*(.+)\s*$', legacy, re.M)
    require(len(password_match) == 1, 'Legacy password structure differs')
    scalar = password_match[0].strip()
    password = json.loads(scalar) if scalar.startswith('"') else scalar.strip("'")
    require(re.fullmatch(r'[A-Za-z0-9_-]{43,128}', password), 'Legacy password does not fit registry')
    code, cert = command(['openssl', 'x509', '-in', '/usr/local/etc/raksmart-hy2/server.crt.pem', '-noout', '-subject'])
    require(code == 0 and 'raksmart-hy2.local' in cert, 'Legacy TLS SNI differs')
    der = subprocess.run(['openssl', 'x509', '-in', '/usr/local/etc/raksmart-hy2/server.crt.pem', '-outform', 'DER'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    require(der.returncode == 0, 'TLS DER conversion failed')
    result['legacy_hy2'] = {'password_length': len(password), 'password_sha256': sha(password.encode()), 'certificate_sha256': sha(der.stdout), 'sni': 'raksmart-hy2.local', 'password_compatible': True}
    result['network'] = {}
    for name, args in [('iptables', ['iptables-save']), ('ip6tables', ['ip6tables-save']), ('qdisc', ['tc', 'qdisc', 'show']), ('listeners', ['ss', '-lntuH'])]:
        code, output = command(args)
        result['network'][name] = {'exit_code': code, 'sha256': sha(output.encode())}
        if name == 'listeners':
            result['network']['listeners']['rows'] = output.splitlines()
    phase = 'authenticated-idle-observation'
    credentials = json.load(sys.stdin)
    cookie = None
    def request(method, path, data=None, csrf=None):
        connection = http.client.HTTPConnection('127.0.0.1', 18787, timeout=15)
        headers = {'Origin': result['origin']}
        if cookie: headers['Cookie'] = cookie
        if csrf: headers['X-CSRF-Token'] = csrf
        if data is not None: headers['Content-Type'] = 'application/json'
        try:
            connection.request(method, '/api/' + path, body=json.dumps(data) if data is not None else None, headers=headers)
            reply = connection.getresponse()
            return reply.status, dict(reply.getheaders()), reply.read()
        finally: connection.close()
    code, headers, body = request('POST', 'login', {'username': credentials['username'], 'password': credentials['password']})
    require(code == 200, 'Existing administrator login failed')
    cookie = headers['Set-Cookie'].split(';', 1)[0]
    csrf = json.loads(body)['csrf']
    try:
        code, headers, body = request('GET', 'state')
        public = json.loads(body)
        require(code == 200 and public.get('server_ip') == result['server'] and public.get('service_active') is True, 'Authenticated state differs')
        job = public.get('job')
        require(not job or job.get('status') != 'running', 'Exit job is active')
        result['authenticated'] = {'admin_login_passed': True, 'exit_job_idle': True, 'exit_count': len(public.get('exits', [])), 'server_port': public.get('server_port'), 'active_target': public.get('active_target')}
    finally:
        code, unused_headers, unused_body = request('POST', 'logout', {}, csrf)
        require(code == 200, 'Read-only session logout failed')
    result.update(success=True, phase='complete')
except BaseException as error:
    result.update(phase=phase, error_type=type(error).__name__, failure='Sanitized baseline verification did not pass')
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result['success'] else 1)
'''

def main():
    if REPORT.exists():
        raise RuntimeError('Baseline report already exists')
    client = ssh.connect()
    try:
        key = client.get_transport().get_remote_server_key()
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
        if key.get_name() != 'ssh-ed25519' or fingerprint != 'IteVQXuF4cffrUYsYkgkpc/m5pTp/2n0CLVK0ej9pzs':
            raise RuntimeError('Host identity differs')
        credentials = json.loads((FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
        stdin, stdout, stderr = client.exec_command('python3 -B -c ' + shlex.quote(REMOTE), timeout=120)
        stdin.write(json.dumps({'username': credentials['username'], 'password': credentials['password']}))
        stdin.flush()
        stdin.channel.shutdown_write()
        output = stdout.read().decode()
        code = stdout.channel.recv_exit_status()
        report = json.loads(output.strip().splitlines()[-1])
        report.update(checked_at=datetime.now(timezone.utc).isoformat(), ssh_hostkey_sha256=fingerprint)
        REPORT.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
        return 0 if code == 0 and report['success'] else 1
    finally:
        client.close()

if __name__ == '__main__':
    raise SystemExit(main())
