"""Probe the exact member sandbox with a temporary loopback-only instance.

Only unique test files in /run/systemd/system and /var/lib are created. All
are removed in finally; the original four service processes and files must
stay unchanged. This is an explicitly authorized deployment readiness test.
"""

import ast
import json
from ssh_access import FOLDER, connect, execute


PROGRAM = r'''
import hashlib, json, os, secrets, socket, subprocess, time, traceback
from pathlib import Path
os.umask(0o077)
identity = secrets.token_hex(8)
unit_name = 'xray-panel-probe-' + identity + '.service'
unit_path = Path('/run/systemd/system') / unit_name
directory = Path('/var/lib') / ('vps-panel-multiuser-probe-' + identity)
config_path = directory / 'config.json'
protected = ['/usr/local/etc/xray/config.json','/usr/local/etc/raksmart-hy2/server.yaml',
             '/etc/systemd/system/xray.service','/etc/systemd/system/raksmart-hy2.service',
             '/etc/systemd/system/vps-panel.service','/etc/systemd/system/caddy.service',
             '/etc/caddy/Caddyfile','/var/lib/vps-panel/auth.private.json','/etc/resolv.conf',
             '/var/lib/vps-panel/base.private.yaml','/var/lib/vps-panel/state.private.json']
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def run(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if check and result.returncode:
        raise RuntimeError('Temporary probe command failed: ' + args[0])
    return result
def processes():
    result = {}
    for service in ['xray.service','raksmart-hy2.service','vps-panel.service','caddy.service']:
        answer = run(['systemctl','show',service])
        fields = dict(line.split('=',1) for line in answer.stdout.decode().splitlines() if '=' in line)
        result[service] = {key:fields[key] for key in ['MainPID','ExecMainStartTimestampMonotonic','ActiveState','SubState']}
    return result
hashes_before = {path:sha(path) for path in protected}
processes_before = processes()
assert not unit_path.exists() and not directory.exists()
stream = socket.socket()
stream.bind(('127.0.0.1',0))
port = stream.getsockname()[1]
stream.close()
config = {'log':{'loglevel':'warning'},
          'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks',
                       'settings':{'auth':'noauth','udp':False}}],
          'outbounds':[{'protocol':'freedom','settings':{'domainStrategy':'UseIPv4'}}]}
unit = TEMPLATE.replace('/usr/local/etc/xray-members/%i/config.json',str(config_path))
unit = unit.replace('/usr/local/etc/xray-members/%i',str(directory))
started = created_unit = created_directory = False
result = {'success':False,'cleanup_complete':False,'original_services_unchanged':False}
try:
    directory.mkdir(mode=0o700)
    created_directory = True
    config_path.write_text(json.dumps(config))
    run(['/usr/local/bin/xray','run','-test','-config',str(config_path)])
    with unit_path.open('x') as file:
        file.write(unit)
    os.chmod(str(unit_path),0o644)
    created_unit = True
    run(['systemd-analyze','verify',str(unit_path)])
    run(['systemctl','daemon-reload'])
    started = True
    run(['systemctl','start',unit_name])
    deadline = time.monotonic() + 8
    while True:
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.5) as connection:
                connection.sendall(b'\x05\x01\x00')
                assert connection.recv(2) == b'\x05\x00', 'Probe SOCKS handshake failed'
            break
        except OSError:
            assert time.monotonic() < deadline, 'Temporary unit did not listen'
            time.sleep(.2)
    run(['systemctl','is-active','--quiet',unit_name])
    assert hashes_before == {path:sha(path) for path in protected}
    assert processes_before == processes()
    result.update(success=True,capability_compatible=True,loopback_socks_handshake_passed=True)
except BaseException:
    result['diagnostic'] = 'Temporary sandbox probe failed; inspect private journal'
    answer = run(['journalctl','--no-pager','-u',unit_name,'-n','25'],check=False)
    (directory / 'journal.private.log').write_bytes(answer.stdout + b'\n' + answer.stderr)
    result['private_journal'] = str(directory / 'journal.private.log')
finally:
    if started:
        run(['systemctl','stop',unit_name],check=False)
        run(['systemctl','reset-failed',unit_name],check=False)
    if created_unit:
        assert unit_path.read_text() == unit, 'Temporary unit changed concurrently'
        unit_path.unlink()
        run(['systemctl','daemon-reload'])
    if created_directory:
        assert directory.parent == Path('/var/lib') and directory.name == 'vps-panel-multiuser-probe-' + identity
        if config_path.exists():
            config_path.unlink()
        journal = directory / 'journal.private.log'
        if journal.exists():
            result['journal_private_text'] = journal.read_text()
            journal.unlink()
        directory.rmdir()
    result['cleanup_complete'] = not unit_path.exists() and not directory.exists()
    result['original_services_unchanged'] = processes_before == processes()
    result['original_files_unchanged'] = hashes_before == {path:sha(path) for path in protected}
print(json.dumps(result))
'''


def main():
    ast.parse(PROGRAM, feature_version=(3,6))
    template = (FOLDER / 'multiuser-xray-panel@.service').read_text(encoding='utf-8')
    program = 'TEMPLATE = ' + repr(template) + '\n' + PROGRAM
    client = connect()
    try:
        code, output, error = execute(client, "python3 - <<'MULTIUSER_SANDBOX_PROBE'\n" + program + '\nMULTIUSER_SANDBOX_PROBE\n', timeout=100)
        (FOLDER / 'multiuser-template-probe.private.log').write_text(output + '\n' + error,encoding='utf-8')
        if code:
            raise RuntimeError('Template probe did not complete; inspect private log')
        report = json.loads(output)
        journal = report.pop('journal_private_text',None)
        if journal is not None:
            (FOLDER / 'multiuser-template-probe-journal.private.log').write_text(journal,encoding='utf-8')
        (FOLDER / 'multiuser-template-probe.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
        print(json.dumps(report))
        if not report['success']:
            raise RuntimeError('Template sandbox probe failed; inspect private journal')
    finally:
        client.close()


if __name__ == '__main__':
    main()
