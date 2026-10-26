import concurrent.futures
import json
import socket
import subprocess
import time

host = '198.200.49.63'
wifi = json.loads(subprocess.run([
    'powershell.exe', '-NoProfile', '-Command',
    'Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | '
    'Where-Object AddressState -eq Preferred | Select-Object -First 1 '
    'IPAddress,InterfaceIndex | ConvertTo-Json -Compress'
], capture_output=True, check=True).stdout.decode('utf-8-sig'))

def check(port, direct):
    start = time.monotonic()
    with socket.socket() as sock:
        sock.settimeout(8)
        if direct:
            sock.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi['InterfaceIndex']))
            sock.bind((wifi['IPAddress'], 0))
        try:
            sock.connect((host, port))
            result = 'connected'
        except OSError as error:
            result = str(error)
    return {'port': port, 'path': 'WLAN' if direct else 'system route',
            'seconds': round(time.monotonic() - start, 3), 'result': result}

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    tasks = [pool.submit(check, port, direct) for port in (443, 47650) for direct in (True, False)]
    for task in concurrent.futures.as_completed(tasks):
        print(json.dumps(task.result()), flush=True)
