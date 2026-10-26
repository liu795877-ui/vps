"""Bounded, isolated HY2 latency and load baseline/after comparison.

Only --mode baseline/after performs network traffic. --check-local is offline.
Fresh means a new isolated Mihomo process's first HTTPS business request. Warm
means a new curl HTTP/TLS connection through one already warmed Mihomo process;
process continuity alone does not prove that QUIC never reconnects. This is not
a complete browser-page test. curl time_connect measures its local proxy, not
the VPS; physical TCP443 connect latency is measured and reported separately.
No web exit, proxy identity, server setting, system route, or FlClash is changed.
Root separately captures server CPU, UDP counters and actual socket queues.
"""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import statistics
import subprocess
import threading
import time

import frontend_motion_access as live
import verify_hy2_clients as helpers


FOLDER = helpers.FOLDER
TEMP_ROOT = FOLDER / 'hy2-latency-private'
LIGHT_URL = 'https://api.ipify.org'
DOWNLOAD_URL = 'https://speed.cloudflare.com/__down?bytes='
UPLOAD_URL = 'https://speed.cloudflare.com/__up'
MAX_TOTAL_SECONDS = 230
MAX_LOAD_TRANSFERS = 16
METRICS_MARKER = b'\nBENCHMARK_METRICS='
METRICS_FORMAT = '{"http_code":%{http_code},"size_download":%{size_download},"size_upload":%{size_upload},"time_connect":%{time_connect},"time_appconnect":%{time_appconnect},"time_pretransfer":%{time_pretransfer},"time_starttransfer":%{time_starttransfer},"time_total":%{time_total}}'


def utc():
    return datetime.now(timezone.utc).isoformat()


def emit(event, phase, **fields):
    print(json.dumps({'event': event, 'phase': phase, 'at': utc(), **fields}), flush=True)


def make_private(directory):
    helpers.require(not directory.is_symlink() and directory.resolve().parent == TEMP_ROOT.resolve()
                    and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe private benchmark directory')
    directory.mkdir(parents=True, exist_ok=False)
    if os.name != 'nt':
        os.chmod(str(directory), 0o700)
        helpers.require(directory.stat().st_mode & 0o777 == 0o700, 'Private directory mode could not be verified')
        return {'verified': True, 'mode': '0700'}
    # New protected DACL replaces all inherited and explicit grants. Write no
    # credentials until current-user + SYSTEM grants have been read back.
    script = "$benchPath = [IO.Path]::GetFullPath('" + str(directory).replace("'", "''") + "')\n" + r'''
$benchSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$benchSystem = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$benchAcl = [Security.AccessControl.DirectorySecurity]::new()
$benchAcl.SetOwner($benchSid)
$benchAcl.SetAccessRuleProtection($true, $false)
foreach ($benchIdentity in @($benchSid, $benchSystem)) {
  $benchRule = [Security.AccessControl.FileSystemAccessRule]::new($benchIdentity,
    [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
    [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow)
  $benchAcl.AddAccessRule($benchRule)
}
[IO.Directory]::SetAccessControl($benchPath, $benchAcl)
$benchActual = [IO.Directory]::GetAccessControl($benchPath)
$benchRules = @($benchActual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if (!$benchActual.AreAccessRulesProtected -or $benchRules.Count -ne 2) { throw 'Private DACL verification failed' }
foreach ($benchRule in $benchRules) {
  if ($benchRule.IdentityReference.Value -notin @($benchSid.Value, $benchSystem.Value) -or
      $benchRule.AccessControlType -ne 'Allow' -or $benchRule.IsInherited -or
      $benchRule.FileSystemRights -ne 'FullControl' -or
      $benchRule.InheritanceFlags -ne 'ContainerInherit, ObjectInherit') { throw 'Unexpected private DACL grant' }
}
if ($benchActual.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $benchSid.Value) { throw 'Private owner verification failed' }
'{"verified":true,"protected_dacl":true,"allow_entries":2}'
'''
    # The checked workspace path is a literal PowerShell single-quoted string.
    encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, creationflags=live.NO_WINDOW)
    helpers.require(result.returncode == 0, 'Private benchmark directory ACL could not be installed')
    value = json.loads(result.stdout.decode('utf-8-sig').strip())
    helpers.require(value.get('verified') is True, 'Private benchmark ACL was not verified')
    return value


def summarize(rows, key, minimum_p95_samples=10):
    values = [row[key] for row in rows if row.get('success') and isinstance(row.get(key), (int, float))]
    result = {'attempts': len(rows), 'successes': len(values),
              'error_rate': round(sum(not row.get('success') for row in rows) / len(rows), 4) if rows else None,
              'median': round(statistics.median(values), 3) if values else None,
              'range': [round(min(values), 3), round(max(values), 3)] if values else None,
              'p95': None, 'p95_minimum_samples': minimum_p95_samples}
    if len(values) >= minimum_p95_samples:
        result['p95'] = round(sorted(values)[math.ceil(.95 * len(values)) - 1], 3)
    return result


def overlap(start, end, windows):
    """Return elapsed coverage by the union of actual active curl windows."""
    intervals = sorted((max(start, a), min(end, b)) for a, b in windows if b > start and a < end)
    covered = 0.0
    previous_end = start
    for a, b in intervals:
        if b > max(a, previous_end):
            covered += b - max(a, previous_end)
        previous_end = max(previous_end, b)
    return min(1.0, covered / (end - start)) if end > start else 0.0


def public_headers(path):
    permitted = ('server', 'cf-ray', 'cf-cache-status')
    values = {}
    try:
        for line in path.read_text(encoding='iso-8859-1').splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                if key.lower() in permitted:
                    values[key.lower()] = value.strip()[:128]
    except OSError:
        pass
    return values


class BenchClient(helpers.IsolatedClient):
    """One fixed HY2 node; never call select(), identity(), or transfer()."""
    def __init__(self, directory, node, clock_start):
        directory.mkdir()
        node = copy.deepcopy(node)
        node.update(name='HY2-BENCHMARK', udp=False)
        super().__init__(directory, [node])
        self.clock_start = clock_start
        self.children = set()
        self.all_children = set()
        self.children_lock = threading.Lock()

    def start(self, deadline=None):
        budget = max(0, deadline - time.monotonic()) if deadline is not None else 50
        helpers.require(budget >= 2, 'Insufficient time to start the isolated client')
        self.log = (self.directory / 'client.private.log').open('w', encoding='utf-8')
        result = subprocess.run([str(helpers.BINARY), '-t', '-d', str(self.directory), '-f', str(self.candidate)],
                                stdout=self.log, stderr=subprocess.STDOUT, timeout=min(30, budget),
                                creationflags=live.NO_WINDOW)
        helpers.require(result.returncode == 0, 'Official Mihomo rejected the isolated client')
        self.process = subprocess.Popen([str(helpers.BINARY), '-d', str(self.directory), '-f', str(self.candidate)],
                                        stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                        creationflags=live.NO_WINDOW)
        ready_deadline = min(time.monotonic() + 20, deadline) if deadline is not None else time.monotonic() + 20
        while True:
            helpers.require(self.process.poll() is None, 'The isolated client exited')
            try:
                self.api('/version')
                return
            except OSError:
                helpers.require(time.monotonic() < ready_deadline, 'The isolated controller did not start')
                time.sleep(.2)

    def request(self, kind, expected_ip, size=0, max_time=8):
        headers = self.directory / ('headers-' + secrets.token_hex(4) + '.private.txt')
        arguments = [helpers.CURL, '--proxy', 'socks5h://127.0.0.1:' + str(self.proxy_port), '--noproxy', '',
            '--connect-timeout', str(min(5, max_time)), '--max-time', str(max_time), '--ssl-no-revoke',
            '--silent', '--show-error', '--dump-header', str(headers), '--write-out',
            METRICS_MARKER.decode('ascii') + METRICS_FORMAT]
        payload = None
        if kind == 'light':
            arguments += [LIGHT_URL]
        elif kind == 'download':
            arguments += ['--output', 'NUL', DOWNLOAD_URL + str(size)]
        elif kind == 'upload':
            arguments += ['--output', 'NUL', '--request', 'POST', '--header', 'Content-Type: application/octet-stream',
                          '--header', 'Expect:', '--data-binary', '@-', UPLOAD_URL]
            payload = bytes(size)
        else:
            raise ValueError('Unknown benchmark request type')
        started = time.monotonic()
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=live.NO_WINDOW)
        with self.children_lock:
            self.children.add(process)
            self.all_children.add(process)
        result = {'kind': kind, 'started_offset_seconds': round(started - self.clock_start, 6)}
        try:
            output, error = process.communicate(payload, timeout=max_time + 3)
            code = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            output, error = process.communicate(timeout=3)
            code = 28
        finally:
            ended = time.monotonic()
            if process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if process.poll() is not None:
                with self.children_lock:
                    self.children.discard(process)
        result.update(ended_offset_seconds=round(ended - self.clock_start, 6),
                      wall_seconds=round(ended - started, 6), curl_exit_code=code,
                      response_identifiers=public_headers(headers))
        try:
            body, metrics = output.rsplit(METRICS_MARKER, 1)
            values = json.loads(metrics.decode('ascii'))
        except (ValueError, UnicodeError):
            body, values = b'', {}
        result.update(http_code=values.get('http_code'), actual_upload_bytes=values.get('size_upload', 0),
                      actual_download_bytes=values.get('size_download', 0), requested_bytes=size)
        for source, target in [('time_connect', 'local_proxy_connect_ms'), ('time_appconnect', 'tls_ready_ms'),
                               ('time_pretransfer', 'pretransfer_ms'), ('time_starttransfer', 'ttfb_ms')]:
            result[target] = round(values[source] * 1000, 3) if isinstance(values.get(source), (int, float)) else None
        result['curl_total_seconds'] = values.get('time_total')
        result['http_wait_after_pretransfer_ms'] = (round(result['ttfb_ms'] - result['pretransfer_ms'], 3)
            if result.get('ttfb_ms') is not None and result.get('pretransfer_ms') is not None else None)
        result['success'] = code == 0 and values.get('http_code') == 200
        if kind == 'light':
            result['egress_matches_current_server_exit'] = body.decode('ascii', 'replace').strip() == expected_ip
            result['success'] = result['success'] and result['egress_matches_current_server_exit']
        else:
            actual = result['actual_upload_bytes'] if kind == 'upload' else result['actual_download_bytes']
            result['success'] = result['success'] and actual == size
            result['mbps_including_request_overhead'] = round(actual * 8 / (ended - started) / 1e6, 3)
        error_text = error.decode('utf-8', 'replace').lower()
        result['error_category'] = 'none' if result['success'] else next((label for needle, label in
            [('timed out', 'timeout'), ('failed to connect', 'connect-failed'), ('ssl', 'tls-failed'),
             ('socks', 'socks-failed'), ('connection reset', 'connection-reset')] if needle in error_text), 'request-failed')
        return result

    def close(self):
        with self.children_lock:
            children = list(self.children)
        for process in children:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
        for process in children:
            try:
                process.communicate(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
        # Even a curl cleanup failure must not prevent closing our Mihomo.
        super().close()


def raw_tcp(wifi, clock_start):
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = {'kind': 'physical_tcp443_connect', 'success': False}
    try:
        stream.settimeout(3)
        stream.setsockopt(socket.IPPROTO_IP, 31, socket.htonl(wifi['InterfaceIndex']))
        stream.bind((wifi['IPAddress'], 0))
        started = time.monotonic()
        result['started_offset_seconds'] = round(started - clock_start, 6)
        stream.connect((live.IP, 443))
        result['success'] = True
    except OSError as error:
        result['error_category'] = 'timeout' if isinstance(error, TimeoutError) else 'connect-failed'
    finally:
        ended = time.monotonic()
        result['ended_offset_seconds'] = round(ended - clock_start, 6)
        start = result.get('started_offset_seconds', ended - clock_start)
        result['tcp_connect_ms'] = round((ended - clock_start - start) * 1000, 3)
        stream.close()
    return result


def phase(name, client, account, wifi, clock_start, seconds, size, global_deadline):
    emit('phase-start', name)
    started_at = utc()
    phase_start = time.monotonic()
    deadline = min(phase_start + seconds, global_deadline)
    transfers, probes = [], []
    lock = threading.Lock()

    def load():
        for index in range(MAX_LOAD_TRANSFERS):
            remaining = deadline - time.monotonic()
            if remaining < 2:
                break
            item = client.request(name, account['expected_ip'], size, max_time=min(45, remaining))
            item['block'] = index + 1
            item['expected_window_end_partial'] = (remaining < 45 and item['curl_exit_code'] == 28)
            with lock:
                transfers.append(item)
            if not item['success']:
                break

    with ThreadPoolExecutor(max_workers=3) as pool:
        worker = pool.submit(load) if name in ('download', 'upload') else None
        while deadline - time.monotonic() >= 2:
            cycle_start = time.monotonic()
            raw = pool.submit(raw_tcp, wifi, clock_start)
            light = pool.submit(client.request, 'light', account['expected_ip'], 0,
                                min(8, max(1, deadline - time.monotonic())))
            probes.extend([raw.result(), light.result()])
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(max(0, 2 - (time.monotonic() - cycle_start)), remaining))
        if worker is not None:
            worker.result()
    byte_key = 'actual_upload_bytes' if name == 'upload' else 'actual_download_bytes'
    windows = [(item['started_offset_seconds'], item['ended_offset_seconds']) for item in transfers
               if item.get(byte_key, 0) > 0 and (item['success'] or item['expected_window_end_partial'])]
    for item in probes:
        item['load_overlap_fraction'] = round(overlap(item['started_offset_seconds'], item['ended_offset_seconds'], windows), 4)
        item['fully_within_load_window'] = name == 'idle' or item['load_overlap_fraction'] >= .999
    raw_rows = [item for item in probes if item['kind'] == 'physical_tcp443_connect' and item['fully_within_load_window']]
    light_rows = [item for item in probes if item['kind'] == 'light' and item['fully_within_load_window']]
    duration = time.monotonic() - phase_start
    actual = sum(item.get(byte_key, 0) for item in transfers)
    active_seconds = sum(item['wall_seconds'] for item in transfers)
    result = {'name': name, 'started_at': started_at, 'finished_at': utc(), 'phase_wall_seconds': round(duration, 3),
              'started_offset_seconds': round(phase_start - clock_start, 6),
              'finished_offset_seconds': round(time.monotonic() - clock_start, 6),
              'load_window_scope': 'active curl request intervals with nonzero payload, including handshake/HTTP; continuous saturation is not proven',
              'requested_window_seconds': seconds, 'load_transfers': transfers, 'probes': probes,
              'actual_load_bytes': actual, 'actual_transfer_seconds': round(active_seconds, 3),
              'observed_load_mbps_including_request_overhead': round(actual * 8 / active_seconds / 1e6, 3) if active_seconds else None,
              'completed_full_blocks': sum(item['success'] for item in transfers),
              'load_byte_cap_reached': len(transfers) == MAX_LOAD_TRANSFERS,
              'raw_tcp_connect_ms': summarize(raw_rows, 'tcp_connect_ms'),
              'proxy_ttfb_ms': summarize(light_rows, 'ttfb_ms'),
              'sufficient_load_coverage': name == 'idle' or min(len(raw_rows), len(light_rows)) >= 4,
              'sufficient_successful_latency_samples': name == 'idle' or min(
                  sum(item['success'] for item in raw_rows), sum(item['success'] for item in light_rows)) >= 4,
              'process_continuity': client.process is not None and client.process.poll() is None,
              'quic_session_reuse_verified': False}
    emit('phase-end', name, phase_wall_seconds=result['phase_wall_seconds'], load_bytes=actual)
    return result


def plan_for(args):
    return {'version': 1, 'light_url': LIGHT_URL, 'download_url': DOWNLOAD_URL + str(args.bytes),
            'upload_url': UPLOAD_URL, 'samples': args.samples, 'payload_bytes': args.bytes,
            'payload_sha256': hashlib.sha256(bytes(args.bytes)).hexdigest(), 'idle_seconds': args.idle_seconds,
            'load_seconds': args.load_seconds, 'max_load_transfers_per_direction': MAX_LOAD_TRANSFERS,
            'single_load_stream': True, 'probe_interval_seconds': 2, 'light_max_time_seconds': 8,
            'load_max_time_seconds': 45, 'max_total_seconds': MAX_TOTAL_SECONDS,
            'deadline_scope': 'soft measurement deadline; subprocess cancellation/controller/cleanup can add bounded overhead',
            'total_load_payload_byte_cap': args.bytes * MAX_LOAD_TRANSFERS * 2,
            'fresh_sample_uses_new_mihomo_process': True, 'load_and_probes_share_warmed_hy2_client': True,
            'complete_page_measured': False, 'external_destination_ip_pinned': False,
            'curl_time_connect_scope': 'local loopback proxy, not VPS RTT',
            'raw_tcp_scope': 'physical WLAN TCP443 connection establishment, not QUIC RTT or packet loss',
            'server_cpu_udp_queue_metrics': 'captured separately by root; global UDP counters do not identify HY2 alone',
            'p95_minimum_successes': 10, 'minimum_fully_covered_probes_per_load_kind': 4}


def run(args):
    report_path = FOLDER / ('hy2-latency-' + args.mode + '.json') if args.mode else None
    report = {'success': False, 'mode': args.mode or 'local-check', 'started_at': utc(), 'server': live.IP,
              'configuration_changes': 0, 'credential_changes': 0, 'exit_changes': 0,
              'fresh_client': {}, 'established_client': {}, 'phases': [], 'cleanup_errors': []}
    directory = TEMP_ROOT / secrets.token_hex(8)
    clients, ssh, sftp = [], None, None
    stage = 'local-gate'
    clock_start = time.monotonic()
    global_deadline = clock_start + MAX_TOTAL_SECONDS
    try:
        helpers.require(not TEMP_ROOT.is_symlink(), 'Unsafe private parent')
        report['private_directory_acl'] = make_private(directory)
        report['core_sha256'] = hashlib.sha256(helpers.BINARY.read_bytes()).hexdigest()
        plan = plan_for(args)
        report['plan'], report['method_sha256'] = plan, helpers.fingerprint(plan)
        report['benchmark_script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if args.check_local:
            client = BenchClient(directory / 'synthetic', helpers.synthetic_nodes()[0], clock_start)
            clients.append(client)
            client.syntax()
            helpers.require(abs(overlap(0, 4, [(0, 2), (1, 3)]) - .75) < 1e-9, 'Window union check failed')
            helpers.require(summarize([{'success': True, 'n': 2}, {'success': True, 'n': 4}], 'n')['median'] == 3,
                            'Summary check failed')
            report.update(success=True, offline_check=True, server_requests=0)
            return report
        stage = 'current-private-reads'
        ssh = helpers.connect()
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(min(30, max(1, global_deadline - time.monotonic())))
        accounts, before_store = helpers.collect_accounts(sftp)
        account = next(item for item in accounts if item['id'] == 'admin')
        state = helpers.private_json(sftp, account['state_path'])
        helpers.require(state.get('active_id') in (None, 'server') and account['expected_ip'] == live.IP,
                        'Benchmark requires the existing admin AUTO server exit; it will not switch it')
        wifi = live.physical_wifi()
        report.update(account_port=443, current_server_exit_ip=account['expected_ip'],
                      profile_sha256=account['profile_sha256'], physical_interface='WLAN',
                      physical_interface_index=wifi['InterfaceIndex'],
                      account_limits={key: before_store.get('users', {}).get('admin', {}).get(key, 0)
                                      for key in ('quota_bytes', 'rate_bps')})
        quota = report['account_limits']['quota_bytes']
        used = sum(helpers.month_totals(before_store, 'admin', datetime.now(timezone.utc).strftime('%Y-%m')).values())
        helpers.require(not quota or quota - used > plan['total_load_payload_byte_cap'] + 16777216,
                        'Remaining normal quota is insufficient for the bounded test byte cap')
        if args.mode == 'after':
            baseline = json.loads((FOLDER / 'hy2-latency-baseline.json').read_text(encoding='utf-8'))
            helpers.require(baseline.get('success') and baseline.get('measurement_valid'), 'Baseline has no valid comparison measurements')
            for key in ('method_sha256', 'core_sha256', 'profile_sha256', 'benchmark_script_sha256', 'account_limits'):
                helpers.require(baseline.get(key) == report[key], 'After measurement differs from the baseline method or client')
            report['baseline_method_verified'] = True
        stage = 'fresh-client-first-requests'
        emit('phase-start', 'fresh-client')
        fresh = []
        for index in range(args.samples):
            helpers.require(global_deadline - time.monotonic() > 20, 'Global measurement budget exhausted')
            client = BenchClient(directory / ('fresh-' + str(index)), account['nodes']['hy2'], clock_start)
            clients.append(client)
            started = time.monotonic()
            client.start(global_deadline)
            item = client.request('light', account['expected_ip'], max_time=min(8, max(1, global_deadline - time.monotonic())))
            item.update(sample=index + 1, mihomo_startup_seconds=round(time.monotonic() - started - item['wall_seconds'], 4),
                        first_business_request=True, new_isolated_client=True)
            fresh.append(item)
            client.close()
        report['fresh_client'] = {'samples': fresh, 'ttfb_ms': summarize(fresh, 'ttfb_ms'),
                                  'label': 'new HY2 client first HTTPS request; no identity or URLTest before it'}
        emit('phase-end', 'fresh-client', samples=len(fresh))
        stage = 'warmed-client-requests'
        emit('phase-start', 'established-client')
        warmed = BenchClient(directory / 'warmed', account['nodes']['hy2'], clock_start)
        clients.append(warmed)
        warmed.start(global_deadline)
        warmup = warmed.request('light', account['expected_ip'], max_time=min(8, max(1, global_deadline - time.monotonic())))
        helpers.require(warmup['success'], 'The warmed client did not use the current server exit')
        warm = []
        for _ in range(args.samples):
            helpers.require(global_deadline - time.monotonic() > 2, 'Global measurement budget exhausted')
            warm.append(warmed.request('light', account['expected_ip'], max_time=min(8, global_deadline - time.monotonic())))
        report['established_client'] = {'warmup': warmup, 'samples': warm, 'ttfb_ms': summarize(warm, 'ttfb_ms'),
            'label': 'new curl HTTPS connections through the same warmed HY2 client', 'quic_session_reuse_verified': False}
        emit('phase-end', 'established-client', samples=len(warm))
        for name in ('idle', 'download', 'upload'):
            stage = 'phase-' + name
            helpers.require(global_deadline - time.monotonic() > 10, 'Global measurement budget exhausted')
            report['phases'].append(phase(name, warmed, account, wifi, clock_start,
                                         args.idle_seconds if name == 'idle' else args.load_seconds,
                                         args.bytes, global_deadline))
        stage = 'settings-preservation'
        after_store = helpers.ledger(sftp)
        registry = helpers.private_json(sftp, helpers.OWNER + '/users.private.json')
        records = {'admin': accounts[0]['record'], **{item['id']: item for item in registry['users']}}
        report['all_settings_preserved'] = all(helpers.settings_hash(
            helpers.private_json(sftp, item['state_path']), records.get(item['id']), after_store) == item['settings_hash']
            for item in accounts)
        month = datetime.now(timezone.utc).strftime('%Y-%m')
        report['normal_monthly_ledger_delta'] = {key: helpers.month_totals(after_store, 'admin', month)[key]
                                                - helpers.month_totals(before_store, 'admin', month)[key]
                                                for key in ('up_bytes', 'down_bytes')}
        report['load_coverage_sufficient'] = all(item['sufficient_load_coverage'] for item in report['phases'])
        report['measurement_completed'] = True
        report['measurement_valid'] = (all(item['success'] for item in fresh + warm)
            and any(item['success'] for item in report['phases'][0]['probes'] if item['kind'] == 'light')
            and all(item['completed_full_blocks'] > 0 for item in report['phases'] if item['name'] != 'idle')
            and report['load_coverage_sufficient']
            and all(item['sufficient_successful_latency_samples'] for item in report['phases']))
        report['success'] = report['all_settings_preserved'] and report['measurement_valid']
        return report
    except Exception as error:
        report.update(failure_stage=stage, error_type=type(error).__name__)
        return report
    finally:
        for client in reversed(clients):
            try:
                client.close()
            except Exception as error:
                report['cleanup_errors'].append('client:' + type(error).__name__)
        for name, resource in [('sftp', sftp), ('ssh', ssh)]:
            if resource is not None:
                try:
                    resource.close()
                except Exception as error:
                    report['cleanup_errors'].append(name + ':' + type(error).__name__)
        try:
            helpers.require(directory.resolve().parent == TEMP_ROOT.resolve() and not directory.is_symlink()
                            and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe private cleanup path')
            if directory.exists():
                shutil.rmtree(str(directory))
        except Exception as error:
            report['cleanup_errors'].append('directory:' + type(error).__name__)
        report['own_mihomo_processes_terminated'] = all(client.process is None or client.process.poll() is not None for client in clients)
        report['own_curl_processes_terminated'] = all(process.poll() is not None for client in clients for process in client.all_children)
        report['temporary_private_files_removed'] = not directory.exists()
        report['finished_at'] = utc()
        report['total_wall_seconds'] = round(time.monotonic() - clock_start, 3)
        if (report['cleanup_errors'] or not report['temporary_private_files_removed']
                or not report['own_mihomo_processes_terminated'] or not report['own_curl_processes_terminated']):
            report['success'] = False
        if report_path is not None:
            report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--mode', choices=('baseline', 'after'))
    mode.add_argument('--check-local', action='store_true')
    parser.add_argument('--samples', type=int, choices=(3, 4), default=3)
    parser.add_argument('--bytes', type=int, choices=(8388608, 16777216), default=8388608)
    parser.add_argument('--idle-seconds', type=int, choices=(12, 16), default=12)
    parser.add_argument('--load-seconds', type=int, choices=(30, 40), default=30)
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result.get('success') else 1)
