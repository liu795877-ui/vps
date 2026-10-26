"""Measure VPS TCP RTT on physical WLAN without changing system routing."""
import concurrent.futures
import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import socket
import statistics
import subprocess
import time

FOLDER = Path(__file__).resolve().parent
HOST = '198.200.49.63'
parser=argparse.ArgumentParser()
parser.add_argument('--count',type=int,default=15)
parser.add_argument('--interval',type=float,default=.25)
parser.add_argument('--ports',type=int,nargs='+',default=[443,47650])
parser.add_argument('--output',default='latency-verification.json')
args=parser.parse_args()
wifi = json.loads(subprocess.run([
    'powershell.exe', '-NoProfile', '-Command',
    'Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | '
    'Where-Object AddressState -eq Preferred | Select-Object -First 1 '
    'IPAddress,InterfaceIndex | ConvertTo-Json -Compress'
], capture_output=True, check=True).stdout.decode('utf-8-sig'))

def measure(host, port, count):
    samples, errors = [], []
    for _ in range(count):
        with socket.socket() as stream:
            stream.settimeout(3)
            stream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi['InterfaceIndex']))
            stream.bind((wifi['IPAddress'], 0))
            start = time.perf_counter()
            try:
                stream.connect((host, port))
                samples.append(round((time.perf_counter()-start)*1000, 2))
            except OSError as error:
                errors.append(type(error).__name__)
        time.sleep(args.interval)
    return {'host':host,'port':port,'count':count,'connected':len(samples),
            'timeouts_or_errors':len(errors), 'errors':errors, 'samples_ms':samples,
            'mean_ms':round(statistics.mean(samples),1) if samples else None,
            'median_ms':round(statistics.median(samples),1) if samples else None,
            'min_ms':min(samples) if samples else None, 'max_ms':max(samples) if samples else None}

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    tasks = [pool.submit(measure, HOST, port, args.count) for port in args.ports]
    tasks.append(pool.submit(measure, wifi['IPAddress'].rsplit('.',1)[0]+'.1', 80, 5))
    checks = [task.result() for task in tasks]
report = {'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
          'method':'TCP connect explicitly bound to physical WLAN (IP_UNICAST_IF)',
          'source_interface':'WLAN','source_ip':wifi['IPAddress'],'checks':checks}
(FOLDER/args.output).write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,ensure_ascii=True))
