"""Short UDP 443 echo probe through physical WLAN, isolated from FlClash.

Explicit invocation opens one temporary UDP listener over existing SSH. It
does not change firewall rules, files, services, TCP 443, or client profiles.
The listener authenticates a random marker, limits response sizes and counts,
and always exits within 24 seconds. TCP and UDP may have different NAT sources.
"""

from datetime import datetime, timedelta, timezone
import json
import secrets
import socket
import statistics
import subprocess
import time

from ssh_access import connect, FOLDER, HOST


REMOTE_PROGRAM = r'''
import json
import os
import select
import socket
import threading
import time

marker = bytes.fromhex(MARKER_HEX)
connection = os.environ.get('SSH_CONNECTION', '').split()
ssh_source = connection[0] if len(connection) == 4 else None
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.settimeout(0.2)
try:
    server.bind(('0.0.0.0', 443))
except OSError:
    server.close()
    print(json.dumps({'ready': False, 'error': 'UDP 443 is already bound or unavailable'}), flush=True)
    raise SystemExit(1)
stop = threading.Event()
counts = {'valid_remote_packets': 0, 'valid_remote_bytes': 0,
          'loopback_packets': 0, 'ignored_packets': 0,
          'ssh_source_match_packets': 0, 'ssh_source_different_packets': 0}
deadline = time.monotonic() + 24


def responder():
    while not stop.is_set() and time.monotonic() < deadline:
        try:
            packet, source = server.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            return
        if not packet.startswith(marker) or not 64 <= len(packet) <= 1440:
            counts['ignored_packets'] += 1
            continue
        if source[0] == '127.0.0.1':
            counts['loopback_packets'] += 1
        else:
            counts['valid_remote_packets'] += 1
            counts['valid_remote_bytes'] += len(packet)
            key = ('ssh_source_match_packets' if source[0] == ssh_source
                   else 'ssh_source_different_packets')
            counts[key] += 1
        try:
            server.sendto(packet, source)
        except OSError:
            continue
        if counts['valid_remote_packets'] >= 9:
            stop.set()


worker = threading.Thread(target=responder)
worker.daemon = True
worker.start()
local_packet = marker + b'L' * (128 - len(marker))
loopback = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
loopback.settimeout(1)
loopback_success = False
try:
    loopback.sendto(local_packet, ('127.0.0.1', 443))
    received, source = loopback.recvfrom(2048)
    loopback_success = received == local_packet and source == ('127.0.0.1', 443)
finally:
    loopback.close()
print(json.dumps({'ready': loopback_success, 'udp_port': 443,
                  'server_loopback_success': loopback_success}), flush=True)
try:
    if not loopback_success:
        stop.set()
    worker.join(max(0, deadline - time.monotonic()))
finally:
    stop.set()
    server.close()
    worker.join(0.5)
print(json.dumps({'server_counts': counts, 'listener_closed': True}), flush=True)
'''


def wifi_information():
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command',
         'Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | '
         'Where-Object AddressState -eq Preferred | Select-Object -First 1 '
         'IPAddress,InterfaceIndex | ConvertTo-Json -Compress'],
        capture_output=True, check=True, timeout=15,
    )
    return json.loads(result.stdout.decode('utf-8-sig'))


def main():
    marker = b'RAK-UDP-PROBE-' + secrets.token_bytes(16)
    program = 'MARKER_HEX = ' + repr(marker.hex()) + '\n' + REMOTE_PROGRAM
    command = "python3 -u - <<'RAK_UDP_PROBE_PY'\n" + program + '\nRAK_UDP_PROBE_PY\n'
    report = {'checked_at': datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
              'server': HOST, 'port': 443, 'transport': 'UDP',
              'path': 'Physical WLAN; active FlClash untouched', 'samples': []}
    client = connect()
    channel = None
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=35)
        stdin.close()
        channel = stdout.channel
        ready = json.loads(stdout.readline())
        report['server'] = {'address': HOST, **ready}
        if not ready.get('ready'):
            raise RuntimeError(ready.get('error', 'Server loopback probe failed'))
        wifi = wifi_information()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi['InterfaceIndex']))
            stream.bind((wifi['IPAddress'], 0))
            stream.connect((HOST, 443))
            stream.settimeout(1.5)
            for sequence, size in enumerate([128, 1200, 1400] * 3):
                prefix = marker + sequence.to_bytes(2, 'big')
                payload = prefix + b'P' * (size - len(prefix))
                started = time.monotonic()
                item = {'sequence': sequence, 'payload_bytes': size, 'success': False}
                try:
                    stream.send(payload)
                    while time.monotonic() - started < 1.5:
                        stream.settimeout(max(0.01, 1.5 - (time.monotonic() - started)))
                        response = stream.recv(2048)
                        if response == payload:
                            item.update(success=True, round_trip_ms=round((time.monotonic() - started) * 1000, 1))
                            break
                except socket.timeout:
                    item['error'] = 'UDP response timeout'
                except OSError as error:
                    item['error'] = 'UDP socket error ' + str(error.errno)
                report['samples'].append(item)
                time.sleep(0.1)
        remaining = stdout.read().decode('utf-8', errors='replace').strip()
        if remaining:
            report['server_completion'] = json.loads(remaining)
        report['remote_exit_code'] = channel.recv_exit_status()
        elapsed = [item['round_trip_ms'] for item in report['samples'] if item['success']]
        report['reply_count'] = len(elapsed)
        report['median_round_trip_ms'] = statistics.median(elapsed) if elapsed else None
        report['public_udp_round_trip_verified'] = bool(elapsed)
        report['limitations'] = 'Small UDP echo samples verify reachability and packet sizes, not QUIC compatibility or sustained throughput.'
    except Exception as error:
        report['error'] = str(error)
    finally:
        if channel is not None:
            channel.close()
        client.close()
        destination = FOLDER / 'udp-probe-result.json'
        destination.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
