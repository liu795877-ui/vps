"""Read-only HY2 host/privacy checks, plus explicitly selected isolated tc tests.

Run `host` and `linux-controls` on Linux. Run `privacy` on the physical Windows
WLAN. The isolated test creates only disposable namespaces and a veth pair;
production firewall/qdisc/default-route fingerprints must remain unchanged.
No private configuration or credentials are returned.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid


PORTS = (443, 1443, 2443)
HOST = '198.200.49.63'


def run(args, check=True, timeout=20):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Verification host command failed')
    return result


def host(active_ports):
    spec = importlib.util.spec_from_file_location('hy2_integration_installer',
                                                Path(__file__).with_name('hy2-integration-remote.py'))
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    baseline = installer.inspect()
    installer.verify_certificate_copies()
    if baseline['legacy']['active'] or baseline['legacy']['enabled'] or installer.LEGACY_CONFIG.exists():
        raise RuntimeError('Legacy single-password ingress is still available')
    instances = {}
    for port in PORTS:
        state = baseline['instances'][str(port)]
        expected = port in active_ports
        if state['active'] != expected or state['enabled'] != expected:
            raise RuntimeError('Unexpected account service lifecycle state')
        entry = {'active': state['active'], 'enabled': state['enabled']}
        if expected:
            path = installer.ACCOUNTS / '{}.yaml'.format(port)
            config = installer.parse_config(path.read_bytes(), port)
            endpoint = 'http://127.0.0.1:{}/'.format(18600 + port)
            try:
                urllib.request.urlopen(endpoint + 'traffic', timeout=2)
                raise RuntimeError('Statistics accepted an unauthenticated request')
            except urllib.error.HTTPError as error:
                if error.code != 401:
                    raise RuntimeError('Unexpected private API authentication result')
            totals = {}
            for resource in ('traffic', 'online'):
                request = urllib.request.Request(endpoint + resource,
                    headers={'Authorization': config['trafficStats']['secret']})
                with urllib.request.urlopen(request, timeout=2) as response:
                    data = json.loads(response.read().decode('utf-8'))
                if not isinstance(data, dict):
                    raise RuntimeError('Invalid private API result')
                if resource == 'traffic':
                    if any(key != 'user' for key in data):
                        raise RuntimeError('Unexpected official password-auth identity')
                    value = data.get('user', {})
                    totals.update(up_bytes=int(value.get('tx', 0)), down_bytes=int(value.get('rx', 0)))
                else:
                    totals['sessions'] = sum(int(value) for value in data.values())
            listeners = run(['ss', '-H', '-lnt']).stdout.decode('utf-8', 'replace').splitlines()
            for private_port in (15600 + port, 18600 + port):
                found = [line.split()[3] for line in listeners
                         if len(line.split()) >= 4 and line.split()[3].endswith(':' + str(private_port))]
                if found != ['127.0.0.1:' + str(private_port)]:
                    raise RuntimeError('Private listener is absent or exposed')
            entry.update(totals, api_authentication=True, private_listeners=True)
        instances[str(port)] = entry
    return {'host_verified': True, 'binary_sha256': baseline['binary_sha256'],
            'certificate_sha256': baseline['certificate_sha256'],
            'legacy_revoked': True, 'instances': instances}


def privacy():
    command = ('Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | '
               'Where-Object AddressState -eq Preferred | Select-Object -First 1 '
               'IPAddress,InterfaceIndex | ConvertTo-Json -Compress')
    interface = json.loads(run(['powershell.exe', '-NoProfile', '-Command', command]).stdout.decode('utf-8-sig'))
    if not isinstance(interface, dict) or not interface.get('IPAddress'):
        raise RuntimeError('Physical WLAN interface is unavailable')
    def probe(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
            stream.settimeout(3)
            stream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(interface['InterfaceIndex']))
            stream.bind((interface['IPAddress'], 0))
            try:
                stream.connect((HOST, port))
                return {'port': port, 'publicly_reachable': True}
            except OSError as error:
                return {'port': port, 'publicly_reachable': False, 'result': type(error).__name__}
    ports = [offset + port for offset in (15600, 18600) for port in PORTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(probe, ports))
    passed = not any(item['publicly_reachable'] for item in results)
    return {'privacy_verified': passed, 'physical_interface': 'WLAN', 'probes': results}


RECEIVER = r'''
import json,socket,threading,time,sys
from pathlib import Path
folder=Path(sys.argv[1]);counts={'tcp':0,'udp':0};lock=threading.Lock()
def tcp_conn(stream):
 try:
  mode=stream.recv(1)
  if mode==b'D':
   until=time.monotonic()+6
   while time.monotonic()<until:stream.sendall(b'x'*65536)
  else:
   while True:
    block=stream.recv(65536)
    if not block:break
    with lock:counts['tcp']+=len(block)
 except OSError:pass
 finally:stream.close()
def tcp_loop(port):
 listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('10.239.0.1',port));listener.listen(10)
 while True:
  stream,address=listener.accept();threading.Thread(target=tcp_conn,args=(stream,),daemon=True).start()
def udp_down(stream,address):
 until=time.monotonic()+5
 while time.monotonic()<until:
  try:stream.sendto(b'x'*1024,address)
  except OSError:break
def udp_loop(port):
 stream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);stream.bind(('10.239.0.1',port))
 while True:
  block,address=stream.recvfrom(2048)
  if block==b'D':threading.Thread(target=udp_down,args=(stream,address),daemon=True).start()
  else:
   with lock:counts['udp']+=len(block)
for port in (443,1443):
 threading.Thread(target=tcp_loop,args=(port,),daemon=True).start();threading.Thread(target=udp_loop,args=(port,),daemon=True).start()
time.sleep(.15);(folder/'ready').write_text('ready')
while True:
 with lock:data=json.dumps(counts)
 (folder/'counts.tmp').write_text(data);(folder/'counts.tmp').replace(folder/'counts.json');time.sleep(.1)
'''

CLIENT = r'''
import socket,threading,time,json,sys
mode=sys.argv[1];duration=float(sys.argv[2]);port=int(sys.argv[3]);only=sys.argv[4] if len(sys.argv)>4 else 'both';counts={'tcp':0,'udp':0};until=time.monotonic()+duration
def tcp():
 stream=socket.socket();stream.settimeout(.5);stream.connect(('10.239.0.1',port));stream.sendall(b'D' if mode=='download' else b'U')
 try:
  while time.monotonic()<until:
   if mode=='download':
    block=stream.recv(65536)
    if not block:break
    counts['tcp']+=len(block)
   else:stream.sendall(b'x'*8192)
 except OSError:pass
 finally:stream.close()
def udp():
 stream=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);stream.settimeout(.5);stream.connect(('10.239.0.1',port))
 if mode=='download':stream.send(b'D')
 try:
  while time.monotonic()<until:
   if mode=='download':counts['udp']+=len(stream.recv(2048))
   else:stream.send(b'x'*1024)
 except OSError:pass
 finally:stream.close()
threads=[threading.Thread(target=fn) for name,fn in (('tcp',tcp),('udp',udp)) if only in ('both',name)]
for thread in threads:thread.start();time.sleep(.1)
for thread in threads:thread.join()
print(json.dumps(counts))
'''


def linux_controls(panel_path):
    if os.geteuid() != 0:
        raise RuntimeError('Isolated network verification requires root')
    sys.path.insert(0, str(Path(panel_path).resolve()))
    from panel import telemetry
    class Shim:
        PanelError = RuntimeError
        @staticmethod
        def json_bytes(value):
            return (json.dumps(value) + '\n').encode('utf-8')
        @staticmethod
        def atomic_write(path, data):
            Path(path).write_bytes(data)
    telemetry._server = lambda: Shim
    def production_fingerprints():
        commands = {'firewall': ['iptables-save'], 'qdisc': ['tc', 'qdisc', 'show', 'dev', 'eth0'],
                    'routes': ['ip', 'route', 'show', 'default']}
        results = {}
        for name, command in commands.items():
            payload = run(command).stdout
            if name == 'firewall':
                # iptables-save includes wall-clock Generated/Completed comments.
                payload = b'\n'.join(line for line in payload.splitlines() if not line.startswith(b'#'))
                # Built-in chain packet/byte counters change with ordinary SSH.
                payload = re.sub(rb'\[[0-9]+:[0-9]+\]', b'[0:0]', payload)
            results[name] = hashlib.sha256(payload).hexdigest()
        return results
    before = production_fingerprints()
    suffix = uuid.uuid4().hex[:8]
    server_ns, client_ns = 'hy2s-' + suffix, 'hy2c-' + suffix
    server_if, client_if = 'hs' + suffix, 'hc' + suffix
    process = None
    result = {}
    with tempfile.TemporaryDirectory(prefix='hy2-isolated-') as temporary:
        folder = Path(temporary)
        try:
            for name in (server_ns, client_ns):
                run(['ip', 'netns', 'add', name])
            run(['ip', 'link', 'add', server_if, 'type', 'veth', 'peer', 'name', client_if])
            for namespace, interface, address, gateway in (
                    (server_ns, server_if, '10.239.0.1/24', '10.239.0.2'),
                    (client_ns, client_if, '10.239.0.2/24', '10.239.0.1')):
                run(['ip', 'link', 'set', interface, 'netns', namespace])
                prefix = ['ip', 'netns', 'exec', namespace]
                run(prefix + ['ip', 'link', 'set', 'lo', 'up'])
                run(prefix + ['ip', 'addr', 'add', address, 'dev', interface])
                run(prefix + ['ip', 'link', 'set', interface, 'up'])
                run(prefix + ['ip', 'route', 'add', 'default', 'via', gateway])
            def runner(arguments, check=True):
                command = ['ip', 'netns', 'exec', server_ns] + arguments
                outcome = run(command, False)
                if check and outcome.returncode:
                    raise RuntimeError('Isolated command failed: ' + repr(arguments) + ': '
                                       + outcome.stderr.decode('utf-8', 'replace')[:700])
                return outcome
            controls = telemetry.LinuxControls(folder / 'controls', runner)
            (folder / 'controls').mkdir()
            external_action = 123456
            runner(['tc', 'actions', 'add', 'action', 'police', 'rate', '1mbit', 'burst', '16000',
                    'index', str(external_action), 'conform-exceed', 'drop/ok'])
            controls.apply(set(), {443: 8000000})
            controls.apply(set(), {443: 8000000})
            (folder / 'receiver.py').write_text(RECEIVER, encoding='utf-8')
            (folder / 'client.py').write_text(CLIENT, encoding='utf-8')
            process = subprocess.Popen(['ip', 'netns', 'exec', server_ns, sys.executable,
                                        str(folder / 'receiver.py'), str(folder)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
            for unused in range(30):
                if (folder / 'ready').exists():
                    break
                time.sleep(.1)
            if not (folder / 'ready').exists():
                raise RuntimeError('Isolated receiver did not become ready')
            def benchmark(mode, duration, port, only='both'):
                return json.loads(run(['ip', 'netns', 'exec', client_ns, sys.executable,
                                      str(folder / 'client.py'), mode, str(duration), str(port), only],
                                     timeout=duration + 5).stdout.decode('utf-8'))
            download = benchmark('download', 4, 443)
            starting = json.loads((folder / 'counts.json').read_text())
            benchmark('upload', 4, 443)
            time.sleep(.25)
            ending = json.loads((folder / 'counts.json').read_text())
            upload = {key: ending[key] - starting[key] for key in ('tcp', 'udp')}
            starting_tcp = ending
            benchmark('upload', 2, 443, 'tcp')
            time.sleep(.25)
            ending_tcp = json.loads((folder / 'counts.json').read_text())
            tcp_upload = ending_tcp['tcp'] - starting_tcp['tcp']
            control = benchmark('download', 1, 1443)
            controls.apply(set(), {443: 4000000})
            changed = benchmark('download', 4, 443)
            rates = {'download_mbps': sum(download.values()) * 8 / 4 / 1000000,
                     'upload_mbps': sum(upload.values()) * 8 / 4 / 1000000,
                     'tcp_only_upload_mbps': tcp_upload * 8 / 2 / 1000000,
                     'changed_combined_download_mbps': sum(changed.values()) * 8 / 4 / 1000000,
                     'unrestricted_other_account_mbps': sum(control.values()) * 8 / 1000000}
            if (not .1 < rates['download_mbps'] < 10.8 or not .1 < rates['upload_mbps'] < 10.8
                    or rates['unrestricted_other_account_mbps'] < 16
                    or not .1 < rates['tcp_only_upload_mbps'] < 10.8
                    or not .1 < rates['changed_combined_download_mbps'] < 5.4
                    or not all(download.values()) or upload['udp'] <= 0):
                raise RuntimeError('Combined TCP/UDP shaping or account isolation failed: '
                                   + json.dumps({'rates': rates, 'download': download, 'upload': upload}))
            # Prove a quota blocks both protocols, then restores both entrances.
            controls.apply({443}, {443: 4000000})
            probe = "import socket,json\nr=[]\nfor t in (socket.SOCK_STREAM,socket.SOCK_DGRAM):\n s=socket.socket(socket.AF_INET,t);s.settimeout(.5)\n try:\n  s.connect(('10.239.0.1',443));s.send(b'D');s.recv(1);r.append(False)\n except OSError:r.append(True)\n finally:s.close()\nprint(json.dumps(r))"
            blocked = json.loads(run(['ip', 'netns', 'exec', client_ns, sys.executable,
                                      '-c', probe]).stdout.decode())
            if blocked != [True, True]:
                raise RuntimeError('TCP and UDP quota were not jointly blocked')
            controls.apply(set(), {})
            actions = runner(['tc', 'actions', 'list', 'action', 'police']).stdout.decode()
            indices = {int(value, 0) for value in re.findall(r'\bpolice\s+(0x[0-9a-fA-F]+|[0-9]+)\b', actions)}
            if indices != {external_action}:
                raise RuntimeError('Owned action removal affected an independent action')
            restored = benchmark('download', 1, 443)
            if sum(restored.values()) * 8 / 1000000 < 16:
                raise RuntimeError('Combined quota or rate removal did not restore traffic')
            result = {'linux_controls_verified': True, 'combined_payload_rates': rates,
                      'quota_blocks_both_transports': True, 'controls_removed': True,
                      'independent_action_preserved': True, 'same_and_changed_rate_updates': True}
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            for namespace in (server_ns, client_ns):
                run(['ip', 'netns', 'del', namespace], False)
            for interface in (server_if, client_if):
                run(['ip', 'link', 'del', interface], False)
            after = production_fingerprints()
            if after != before:
                raise RuntimeError('Production network fingerprints changed during isolated test: '
                                   + ','.join(key for key in before if before[key] != after[key]))
    if production_fingerprints() != before:
        raise RuntimeError('Production network fingerprints changed after isolated test')
    result['production_network_unchanged'] = True
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('host', 'privacy', 'linux-controls'))
    parser.add_argument('--active-ports', default='443')
    parser.add_argument('--panel-path')
    args = parser.parse_args()
    try:
        if args.operation == 'host':
            ports = {int(value) for value in args.active_ports.split(',') if value}
            if not ports <= set(PORTS):
                raise ValueError('Unsupported active account entrance')
            result = host(ports)
        elif args.operation == 'privacy':
            result = privacy()
        else:
            if not args.panel_path:
                parser.error('linux-controls requires --panel-path')
            result = linux_controls(args.panel_path)
        print(json.dumps(result, sort_keys=True))
        if args.operation == 'privacy' and not result['privacy_verified']:
            raise SystemExit(1)
    except Exception as error:
        failure = {'success': False, 'operation': args.operation,
                   'error_type': type(error).__name__}
        if args.operation == 'linux-controls':
            failure['diagnostic'] = str(error)
        print(json.dumps(failure))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
