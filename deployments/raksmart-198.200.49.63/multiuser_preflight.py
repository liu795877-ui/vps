"""Read-only multi-user resource, process and preservation baseline.

Private server state stays in the .private.json artifact. Printed fields are a
strict public whitelist; unit environment/credentials are never copied out.
"""

import ast
from datetime import datetime, timezone
import json
import shlex
from ssh_access import FOLDER, connect, execute


PROGRAM = r'''
import hashlib, json, os, socket, subprocess
from pathlib import Path

protected = ['/usr/local/etc/xray/config.json', '/usr/local/etc/raksmart-hy2/server.yaml',
             '/etc/systemd/system/xray.service', '/etc/systemd/system/raksmart-hy2.service',
             '/etc/systemd/system/vps-panel.service', '/etc/systemd/system/caddy.service',
             '/etc/caddy/Caddyfile', '/var/lib/vps-panel/auth.private.json',
             '/etc/resolv.conf', '/var/lib/vps-panel/base.private.yaml']
properties = ['ActiveState', 'SubState', 'UnitFileState', 'MainPID',
              'ActiveEnterTimestampMonotonic', 'ExecMainStartTimestampMonotonic', 'NRestarts']
services = {}
for service in ['xray.service', 'raksmart-hy2.service', 'vps-panel.service', 'caddy.service']:
    result = subprocess.run(['systemctl', 'show', service], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=12)
    if result.returncode:
        raise RuntimeError('Could not inspect service')
    values = dict(line.split('=', 1) for line in result.stdout.decode().splitlines() if '=' in line)
    services[service] = {key: values[key] for key in properties if key in values}
unit = Path('/etc/systemd/system/xray.service').read_text()
allowed = ['Type', 'User', 'Group', 'WorkingDirectory', 'Restart', 'RestartSec',
           'LimitNOFILE', 'NoNewPrivileges', 'PrivateTmp', 'PrivateDevices',
           'ProtectSystem', 'ProtectHome', 'ReadOnlyPaths', 'ReadWritePaths',
           'CapabilityBoundingSet', 'AmbientCapabilities', 'RestrictAddressFamilies']
safe_unit = {}
for line in unit.splitlines():
    key, sep, value = line.partition('=')
    if sep and key.strip() in allowed:
        safe_unit[key.strip()] = value.strip()
panel_unit = {}
for line in Path('/etc/systemd/system/vps-panel.service').read_text().splitlines():
    key, sep, value = line.partition('=')
    if sep and key.strip() in allowed + ['ReadWriteDirectories']:
        panel_unit[key.strip()] = value.strip()
memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
resources = {'cpu_count': os.cpu_count(), 'mem_total_kib': int(memory['MemTotal'].split()[0]),
             'mem_available_kib': int(memory['MemAvailable'].split()[0]),
             'load_average': list(os.getloadavg()),
             'disk_free_bytes': os.statvfs('/var/lib/vps-panel').f_bavail * os.statvfs('/var/lib/vps-panel').f_frsize}
ports = {}
for port in [1443, 2443]:
    stream = socket.socket()
    try:
        stream.bind(('0.0.0.0', port))
        ports[str(port)] = {'local_bind_available': True}
    except OSError:
        ports[str(port)] = {'local_bind_available': False}
    finally:
        stream.close()
firewall = {}
for tool in ['firewall-cmd', 'iptables', 'nft']:
    from shutil import which
    firewall[tool] = bool(which(tool))
for service in ['firewalld.service', 'iptables.service']:
    answer = subprocess.run(['systemctl', 'is-active', service], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=10)
    firewall[service] = answer.stdout.decode().strip()
response = subprocess.run(['iptables', '-S'], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=12)
rules = response.stdout.decode().splitlines()
firewall['iptables_command_success'] = response.returncode == 0
firewall['policies'] = [line for line in rules if line.startswith('-P ')]
firewall['rule_count'] = len([line for line in rules if line.startswith('-A ')])
firewall['ports_1443_2443_mentions'] = len([line for line in rules if '1443' in line or '2443' in line])
missing = [path for path in protected if not Path(path).is_file() or Path(path).is_symlink()]
hashes = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in protected if path not in missing}
state = json.loads(Path('/var/lib/vps-panel/state.private.json').read_text())
output = {'state': state, 'protected_sha256': hashes, 'missing_paths': missing,
          'resources': resources, 'ports': ports, 'services': services,
          'firewall': firewall, 'xray_safe_unit_fields': safe_unit,
          'panel_safe_unit_fields': panel_unit,
          'os_release': Path('/etc/os-release').read_text(),
          'python_version': __import__('sys').version.split()[0]}
print(json.dumps(output))
'''


def main():
    ast.parse(PROGRAM, feature_version=(3, 6))
    client = connect()
    try:
        command = "python3 - <<'MULTIUSER_PREFLIGHT'\n" + PROGRAM + "\nMULTIUSER_PREFLIGHT\n"
        code, output, error = execute(client, command, timeout=70)
        if code:
            (FOLDER / 'multiuser-preflight-error.private.log').write_text(error, encoding='utf-8')
            raise RuntimeError('Read-only preflight failed; inspect private log')
        baseline = json.loads(output)
        baseline['checked_at'] = datetime.now(timezone.utc).isoformat()
        (FOLDER / 'multiuser-preflight.private.json').write_text(json.dumps(baseline, indent=2), encoding='utf-8')
        state = baseline['state']
        public = {key: value for key, value in baseline.items() if key not in ['state', 'os_release']}
        public.update(success=True, existing_exit_count=len(state['exits']),
                      active_target='server' if state['active_id'] in (None, 'server') else 'static',
                      active_id_preserved=True, registry_exists=None)
        (FOLDER / 'multiuser-preflight.json').write_text(json.dumps(public, indent=2), encoding='utf-8')
        print(json.dumps(public))
    finally:
        client.close()


if __name__ == '__main__':
    main()
