import concurrent.futures
import json
from pathlib import Path
import shlex
import socket
import subprocess
import time
from ssh_access import connect, FOLDER

wifi = json.loads(subprocess.run([
    'powershell.exe', '-NoProfile', '-Command',
    'Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | '
    'Where-Object AddressState -eq Preferred | Select-Object -First 1 '
    'IPAddress,InterfaceIndex | ConvertTo-Json -Compress'
], capture_output=True, check=True).stdout.decode('utf-8-sig'))

remote_code = '''
import socket, select, time
listeners = []
for port in (8443, 25443):
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0', port))
    listener.listen(8)
    listeners.append(listener)
print('READY', flush=True)
deadline = time.monotonic() + 12
while time.monotonic() < deadline:
    readable, _, _ = select.select(listeners, [], [], 0.5)
    for listener in readable:
        peer, address = listener.accept()
        print('ACCEPTED_PORT', listener.getsockname()[1], flush=True)
        peer.close()
for listener in listeners:
    listener.close()
'''

def check(port):
    start = time.monotonic()
    with socket.socket() as sock:
        sock.settimeout(6)
        sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi['InterfaceIndex']))
        sock.bind((wifi['IPAddress'], 0))
        try:
            sock.connect(('198.200.49.63', port))
            result = 'connected'
        except OSError as error:
            result = str(error)
    return {'port': port, 'path': 'WLAN', 'seconds': round(time.monotonic()-start,3), 'result': result}

client = connect()
try:
    stdin, stdout, stderr = client.exec_command('python3 -u -c ' + shlex.quote(remote_code), timeout=20)
    stdin.close()
    if stdout.readline().strip() != 'READY':
        raise RuntimeError('Remote temporary listeners failed to start')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(check, (8443, 25443)))
    remote_output = stdout.read().decode('utf-8', errors='replace')
    remote_error = stderr.read().decode('utf-8', errors='replace')
    report = {'results': results, 'remote_output': remote_output, 'remote_error': remote_error}
    (FOLDER/'alternate-port-tests.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report))
finally:
    client.close()
