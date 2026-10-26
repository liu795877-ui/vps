"""Bounded HY2 idle/session evidence and profile comparison.

Only --mode performs network I/O. --check-local runs synthetic official-core
syntax tests only. Never changes exits, production profiles, server settings,
credentials, routes, or the user's running proxy. A first business request has
no URLTest/identity warmup. Each warm sample uses a fresh curl HTTPS connection
through the same isolated Mihomo process; this is not HTTP connection reuse.
"""

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import subprocess
import time

import yaml

import benchmark_hy2_latency as base
import verify_hy2_clients as helpers


PROFILES = ('standard', 'conservative', 'aggressive')
BLOCK_BYTES = 8388608
MAX_BLOCKS = 8
IDLE_WAITS = (30, 60, 180)


# Read-only, sanitized output. Credentials never leave the remote program.
# Journal evidence covers the account entrance, not an isolated client alone.
SNAPSHOT_PROGRAM = r'''
import hashlib, json, re, subprocess, sys, time
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener
identity, port, since = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
snapshot_stage = 'validate-input'
assert identity == 'admin' or re.fullmatch(r'[a-f0-9]{16}', identity)
assert port in (443, 2443) and since >= 0
registry = json.loads(Path('/var/lib/vps-panel/hy2.private.json').read_text())
entry = registry['accounts'][identity]
assert registry['enabled'] and entry['port'] == port
query = Request('http://127.0.0.1:' + str(18600 + port) + '/online',
                headers={'Authorization': entry['api_secret']})
snapshot_stage = 'online-api'
with build_opener(ProxyHandler({})).open(query, timeout=3) as response:
    online = json.loads(response.read().decode('utf-8'))
assert isinstance(online, dict) and not set(online) - {'user'}
count = online.get('user', 0)
assert type(count) is int and count >= 0
service = 'raksmart-hy2@' + str(port) + '.service'
snapshot_stage = 'process-epoch'
epoch = subprocess.check_output(['systemctl', 'show', service,
    '--property=MainPID', '--property=ExecMainStartTimestampMonotonic'], timeout=4)
snapshot_stage = 'runtime-config'
config = json.loads(Path('/usr/local/etc/raksmart-hy2/accounts/' + str(port) + '.yaml').read_text())
events, parsed_lines = [], 0
query_start = since or time.time() - 30
snapshot_stage = 'journal-query'
journal = subprocess.run(['journalctl', '-u', service, '--since', '@' + str(query_start),
    '--no-pager', '-o', 'json', '-n', '500'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
if journal.returncode == 0:
    snapshot_stage = 'journal-parse'
    for line in journal.stdout.decode('utf-8', 'replace').splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        parsed_lines += 1
        message = item.get('MESSAGE', '')
        # systemd's JSON mode emits binary/non-printable MESSAGE fields as
        # byte arrays; official HY2's ANSI logger triggers this on CentOS 7.
        if isinstance(message, list) and all(type(v) is int and 0 <= v <= 255 for v in message):
            message = bytes(message).decode('utf-8', 'replace')
        elif isinstance(message, list) and all(isinstance(v, str) for v in message):
            message = '\n'.join(message)
        if not isinstance(message, str):
            continue
        lower = message.lower()
        kind = ('disconnected' if 'client disconnected' in lower else
                'connected' if 'client connected' in lower else None)
        if kind:
            detail = {}
            try:
                detail = json.loads(message[message.index('{'):])
            except (ValueError, TypeError):
                pass
            if not isinstance(detail, dict):
                detail = {}
            addr = detail.get('addr')
            events.append({'event': kind, 'unix_microseconds': item.get('__REALTIME_TIMESTAMP'),
                'remote_address_sha256': hashlib.sha256(str(addr).encode()).hexdigest() if addr else None})
print(json.dumps({'server_unix_seconds': time.time(), 'online_sessions': count,
    'process_epoch_sha256': hashlib.sha256(epoch).hexdigest(),
    'server_config_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
    'server_congestion': config.get('congestion'),
    'ignore_client_bandwidth': config.get('ignoreClientBandwidth'),
    'journal_available': journal.returncode == 0, 'journal_parsed_lines': parsed_lines,
    'journal_event_scope': 'all sessions on this account entrance',
    'journal_connected_events': sum(e['event'] == 'connected' for e in events),
    'journal_disconnected_events': sum(e['event'] == 'disconnected' for e in events),
    'journal_events': events}))
'''


class SnapshotFailure(RuntimeError):
    def __init__(self, detail):
        super().__init__('Read-only HY2 session snapshot failed')
        self.safe_detail = detail


def wrapped_snapshot_program():
    # No exception text, raw journal, config, API bodies or credentials reach
    # the local report even when a remote parser fails.
    return ('import sys, traceback, json\ntry:\n' +
        ''.join('    ' + line + '\n' for line in SNAPSHOT_PROGRAM.splitlines()) +
        "except BaseException as error:\n"
        "    frame = traceback.extract_tb(sys.exc_info()[2])[-1]\n"
        "    print(json.dumps({'snapshot_failure': {'error_type': type(error).__name__,"
        " 'program_line': max(0, frame.lineno - 2), 'stage': globals().get('snapshot_stage', 'startup')}}))\n"
        "    sys.exit(2)\n")


def snapshot(ssh, account, since=0):
    command = 'python3 -c ' + shlex.quote(wrapped_snapshot_program()) + ' ' + shlex.quote(account['id'])
    command += ' ' + str(account['port']) + ' ' + str(since)
    code, output, _ = helpers.execute(ssh, command, timeout=15)
    result = json.loads(output)
    if code != 0:
        raise SnapshotFailure(result.get('snapshot_failure', {'error_type': 'RemoteFailure', 'stage': 'remote-program'}))
    helpers.require(isinstance(result.get('online_sessions'), int), 'Invalid session evidence')
    return result


def node_for(node, profile):
    result = copy.deepcopy(node)
    result['bbr-profile'] = profile
    return result


def node_without_profile_hash(node):
    value = copy.deepcopy(node)
    value.pop('bbr-profile', None)
    return helpers.fingerprint(value)


def profile_contract(directory):
    """Syntax acceptance alone cannot prove field consumption or invalid handling."""
    result = {'valid': {}, 'invalid_value_rejected': False}
    node = helpers.synthetic_nodes()[0]
    for name in (*PROFILES, 'INVALID-BBR-PROFILE-FIELD-CONSUMPTION-CHECK'):
        child = directory / ('syntax-' + name)
        child.mkdir()
        client = helpers.IsolatedClient(child, [node_for(node, name)])
        log_path = child / 'syntax.private.log'
        with log_path.open('w', encoding='utf-8') as stream:
            checked = subprocess.run([str(helpers.BINARY), '-t', '-d', str(child), '-f', str(client.candidate)],
                stdout=stream, stderr=subprocess.STDOUT, timeout=15, creationflags=base.live.NO_WINDOW)
        text = log_path.read_text(encoding='utf-8', errors='replace').lower()
        if name in PROFILES:
            result['valid'][name] = checked.returncode == 0
        else:
            result['invalid_value_rejected'] = checked.returncode != 0 and ('bbr' in text or 'congestion' in text)
    result['all_valid_profiles_accepted'] = all(result['valid'].values())
    result['field_consumption_demonstrated_by_negative_syntax'] = result['invalid_value_rejected']
    result['negative_syntax_limit'] = 'Unknown values may fall back to standard. Consumption must also be checked against the exact installed version source.'
    return result


def request(client, account, deadline, **fields):
    helpers.require(deadline - time.monotonic() > 1, 'Measurement budget exhausted')
    item = client.request('light', account['expected_ip'], max_time=min(8, deadline - time.monotonic()))
    item.update(fields)
    return item


def metrics_summary(rows):
    return {name: base.summarize(rows, name) for name in
            ('local_proxy_connect_ms', 'tls_ready_ms', 'pretransfer_ms', 'ttfb_ms', 'http_wait_after_pretransfer_ms')}


def wait_idle(seconds, phase, deadline):
    started = time.monotonic()
    while seconds - (time.monotonic() - started) > .01:
        remaining = seconds - (time.monotonic() - started)
        helpers.require(deadline - time.monotonic() >= remaining, 'Idle budget exhausted')
        base.emit('idle-progress', phase, elapsed_seconds=round(time.monotonic() - started, 1),
                  remaining_seconds=round(remaining, 1))
        time.sleep(min(30, remaining))
    return round(time.monotonic() - started, 3)


def continuity(before, after, baseline, client):
    connected = after['journal_connected_events'] - before['journal_connected_events']
    disconnected = after['journal_disconnected_events'] - before['journal_disconnected_events']
    epoch_same = before['process_epoch_sha256'] == after['process_epoch_sha256']
    journal_usable = (before['journal_available'] and after['journal_available']
                      and baseline['journal_connected_events'] >= 1)
    return {'isolated_client_process_alive': client.process.poll() is None,
        'server_process_epoch_preserved': epoch_same,
        'online_sessions_before': before['online_sessions'], 'online_sessions_after': after['online_sessions'],
        'account_connected_event_delta': connected, 'account_disconnected_event_delta': disconnected,
        'journal_observed_initial_connection': baseline['journal_connected_events'] >= 1,
        'no_account_reconnect_event_observed': journal_usable and epoch_same and connected == 0 and disconnected == 0,
        'reconnection_event_observed': journal_usable and (connected > 0 or disconnected > 0),
        'isolated_quic_session_reuse_conclusively_verified': False,
        'scope_limit': 'Journal and online counters cover all account sessions; time alone is not session evidence.'}


def load_phase(name, client, account, wifi, clock_start, seconds, global_deadline):
    base.emit('phase-start', name)
    started = time.monotonic()
    deadline = min(started + seconds, global_deadline)
    transfers, probes = [], []

    def load():
        for index in range(MAX_BLOCKS):
            remaining = deadline - time.monotonic()
            if remaining < 2:
                break
            row = client.request(name, account['expected_ip'], BLOCK_BYTES, max_time=min(16, remaining))
            row['block'] = index + 1
            row['expected_window_end_partial'] = row['curl_exit_code'] == 28 and remaining < 16
            transfers.append(row)
            if not row['success']:
                break

    with ThreadPoolExecutor(max_workers=3) as pool:
        worker = pool.submit(load) if name != 'idle' else None
        while deadline - time.monotonic() >= 2:
            cycle_start = time.monotonic()
            raw = pool.submit(base.raw_tcp, wifi, clock_start)
            light = pool.submit(client.request, 'light', account['expected_ip'], 0,
                                min(6, deadline - time.monotonic()))
            probes.extend([raw.result(), light.result()])
            if deadline > time.monotonic():
                time.sleep(min(max(0, 2 - (time.monotonic() - cycle_start)), deadline - time.monotonic()))
        if worker is not None:
            worker.result()
    byte_key = 'actual_upload_bytes' if name == 'upload' else 'actual_download_bytes'
    windows = [(row['started_offset_seconds'], row['ended_offset_seconds']) for row in transfers
               if row.get(byte_key, 0) and (row['success'] or row['expected_window_end_partial'])]
    for row in probes:
        row['load_overlap_fraction'] = round(base.overlap(row['started_offset_seconds'], row['ended_offset_seconds'], windows), 4)
        row['fully_within_load_window'] = name == 'idle' or row['load_overlap_fraction'] >= .999
    raw = [r for r in probes if r['kind'] == 'physical_tcp443_connect' and r['fully_within_load_window']]
    light = [r for r in probes if r['kind'] == 'light' and r['fully_within_load_window']]
    actual = sum(r.get(byte_key, 0) for r in transfers)
    active = sum(r['wall_seconds'] for r in transfers)
    result = {'name': name, 'requested_window_seconds': seconds,
        'phase_wall_seconds': round(time.monotonic() - started, 3), 'load_transfers': transfers, 'probes': probes,
        'actual_load_bytes': actual, 'maximum_requested_payload_bytes': BLOCK_BYTES * MAX_BLOCKS,
        'completed_full_blocks': sum(r['success'] for r in transfers),
        'load_byte_cap_reached': len(transfers) == MAX_BLOCKS,
        'actual_transfer_seconds': round(active, 3),
        'observed_load_mbps_including_request_overhead': round(actual * 8 / active / 1e6, 3) if active else None,
        'physical_tcp_connect_ms': base.summarize(raw, 'tcp_connect_ms'),
        'light_request_stages': metrics_summary(light),
        'minimum_fully_covered_successful_probes': 2,
        'sufficient_load_coverage': name == 'idle' or min(sum(r['success'] for r in raw), sum(r['success'] for r in light)) >= 2,
        'load_window_scope': 'active request intervals including handshake/HTTP; continuous saturation is not proven'}
    base.emit('phase-end', name, load_bytes=actual, phase_wall_seconds=result['phase_wall_seconds'])
    return result


def plan(args):
    return {'version': 1, 'mode': args.mode, 'light_url': base.LIGHT_URL,
        'download_url': base.DOWNLOAD_URL + str(BLOCK_BYTES), 'upload_url': base.UPLOAD_URL,
        'payload_bytes': BLOCK_BYTES, 'payload_sha256': hashlib.sha256(bytes(BLOCK_BYTES)).hexdigest(),
        'max_blocks_per_direction': MAX_BLOCKS, 'max_payload_per_direction': BLOCK_BYTES * MAX_BLOCKS,
        'fresh_samples': 3 if args.mode == 'profile' else 1, 'warm_samples': 4,
        'idle_wait_seconds': list(IDLE_WAITS) if args.mode == 'idle' else [],
        'idle_load_baseline_seconds': 6, 'load_seconds': args.load_seconds,
        'light_target_ip_pinned': False, 'cloudflare_region_from_response_cf_ray': True,
        'client_startup_excluded_from_request_ttfb': True,
        'first_business_request_has_no_identity_or_urltest_warmup': True,
        'warm_scope': 'fresh curl HTTPS connections through already-used isolated Mihomo',
        'load_and_probes_share_client': True, 'never_calls_controller_delete_connections': True,
        'tcp_scope': 'physical WLAN TCP443 connect, not QUIC RTT',
        'curl_connect_scope': 'local loopback proxy, not VPS RTT',
        'complete_page_measured': False,
        'session_evidence_scope': 'server account online count, process epoch, sanitized journal events',
        'normal_quota_applies': True, 'p95_minimum_samples': 10}


def run(args):
    label = args.label or args.mode or 'local'
    report_path = helpers.FOLDER / ('tuning-' + label + '.json') if args.mode else None
    clock_start = time.monotonic()
    deadline = clock_start + (420 if args.mode == 'idle' else 125)
    directory = base.TEMP_ROOT / secrets.token_hex(8)
    clients, ssh, sftp = [], None, None
    report = {'success': False, 'label': label, 'mode': args.mode or 'local-check', 'started_at': base.utc(),
        'server': base.live.IP, 'configuration_changes': 0, 'exit_changes': 0, 'credential_changes': 0,
        'client_profile': args.client_profile, 'cleanup_errors': [], 'fresh_client': {},
        'established_client': {}, 'idle_observations': [], 'phases': []}
    stage = 'local-gate'
    try:
        helpers.require(not base.TEMP_ROOT.is_symlink(), 'Unsafe private parent')
        report['private_directory_acl'] = base.make_private(directory)
        report['core_sha256'] = hashlib.sha256(helpers.BINARY.read_bytes()).hexdigest()
        report['benchmark_script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['plan'] = plan(args)
        report['method_sha256'] = helpers.fingerprint(report['plan'])
        report['installed_core_profile_contract'] = profile_contract(directory)
        if args.check_local:
            ast.parse(SNAPSHOT_PROGRAM, feature_version=(3, 6))
            ast.parse(wrapped_snapshot_program(), feature_version=(3, 6))
            original = helpers.synthetic_nodes()[0]
            changed = node_for(original, 'aggressive')
            helpers.require(node_without_profile_hash(original) == node_without_profile_hash(changed), 'Node normalization failed')
            helpers.require(base.overlap(0, 4, [(0, 2), (1, 3)]) == .75, 'Window union failed')
            report.update(success=True, offline_check=True, server_requests=0,
                          all_profile_syntax_accepted=report['installed_core_profile_contract']['all_valid_profiles_accepted'])
            return report
        # Root checks the exact installed version source; invalid values can
        # legitimately fall back to standard rather than cause syntax failure.
        helpers.require(report['installed_core_profile_contract']['all_valid_profiles_accepted'],
                        'Installed Mihomo rejected a valid profile syntax')
        stage = 'current-private-reads'
        ssh = helpers.connect()
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(20)
        accounts, before_store = helpers.collect_accounts(sftp)
        account = next(a for a in accounts if a['port'] == args.account_port)
        state = helpers.private_json(sftp, account['state_path'])
        helpers.require(state.get('active_id') in (None, 'server') and account['expected_ip'] == base.live.IP,
                        'Benchmark requires this account current AUTO server exit and will not switch it')
        wifi = base.live.physical_wifi()
        node = node_for(account['nodes']['hy2'], args.client_profile)
        report.update(account_port=account['port'], account_identifier_sha256=helpers.fingerprint(account['id']),
            current_server_exit_ip=account['expected_ip'], profile_sha256=account['profile_sha256'],
            node_sha256_excluding_bbr_profile=node_without_profile_hash(node),
            isolated_node_sha256=helpers.fingerprint(node),
            all_settings_before_sha256=helpers.fingerprint([a['settings_hash'] for a in accounts]),
            physical_interface='WLAN', physical_interface_index=wifi['InterfaceIndex'],
            account_limits={k: before_store.get('users', {}).get(account['id'], {}).get(k, 0)
                            for k in ('quota_bytes', 'rate_bps')})
        month = datetime.now(timezone.utc).strftime('%Y-%m')
        used = sum(helpers.month_totals(before_store, account['id'], month).values())
        quota = report['account_limits']['quota_bytes']
        byte_cap = 2 * BLOCK_BYTES * MAX_BLOCKS if args.mode == 'profile' else 0
        helpers.require(not quota or quota - used > byte_cap + 16777216, 'Remaining normal quota insufficient for byte cap')
        initial = snapshot(ssh, account)
        since = initial['server_unix_seconds']
        report['server_initial'] = initial
        if args.expected_server_profile:
            helpers.require(initial.get('server_congestion', {}).get('bbrProfile') == args.expected_server_profile,
                            'Running server profile differs from expected profile')
        stage = 'fresh-client'
        fresh = []
        warmed = None
        for index in range(3 if args.mode == 'profile' else 1):
            base.emit('phase-start', 'fresh-client', sample=index + 1)
            client = base.BenchClient(directory / ('fresh-' + str(index)), node, clock_start)
            clients.append(client)
            start = time.monotonic()
            client.start(deadline)
            startup = time.monotonic() - start
            row = request(client, account, deadline, sample=index + 1, first_business_request=True,
                          new_isolated_client=True, mihomo_startup_seconds=round(startup, 4), startup_warming_requests=0)
            fresh.append(row)
            base.emit('phase-end', 'fresh-client', sample=index + 1, success=row['success'], ttfb_ms=row['ttfb_ms'])
            if index == (2 if args.mode == 'profile' else 0):
                warmed = client
            else:
                client.close()
        report['fresh_client'] = {'samples': fresh, 'stages': metrics_summary(fresh)}
        helpers.require(fresh[-1]['success'], 'First business request did not use current server exit')
        stage = 'continuous-client'
        warm = [request(warmed, account, deadline, sample=i + 1, first_business_request=False,
                        new_isolated_client=False) for i in range(4)]
        report['established_client'] = {'samples': warm, 'stages': metrics_summary(warm),
            'startup_warming_requests': 1, 'label': 'same client as the final fresh sample, now used once'}
        base.emit('phase-end', 'continuous-client', samples=4,
                  ttfb_median=report['established_client']['stages']['ttfb_ms']['median'])
        stage = 'session-baseline'
        baseline = snapshot(ssh, account, since)
        report['server_after_first_requests'] = baseline
        if args.mode == 'idle':
            previous = baseline
            for seconds in IDLE_WAITS:
                stage = 'idle-' + str(seconds)
                waited = wait_idle(seconds, stage, deadline)
                before_request = snapshot(ssh, account, since)
                row = request(warmed, account, deadline, after_idle_seconds=waited)
                after_request = snapshot(ssh, account, since)
                report['idle_observations'].append({'requested_idle_seconds': seconds,
                    'actual_wait_seconds': waited, 'first_request_after_idle': row,
                    'server_before_request': before_request, 'server_after_request': after_request,
                    'continuity_during_idle': continuity(previous, before_request, baseline, warmed),
                    'continuity_including_request': continuity(previous, after_request, baseline, warmed)})
                previous = after_request
                base.emit('phase-end', stage, success=row['success'], ttfb_ms=row['ttfb_ms'],
                    connected_event_delta=report['idle_observations'][-1]['continuity_including_request']['account_connected_event_delta'])
        else:
            for name in ('idle', 'download', 'upload'):
                stage = 'phase-' + name
                report['phases'].append(load_phase(name, warmed, account, wifi, clock_start,
                                                   6 if name == 'idle' else args.load_seconds, deadline))
        stage = 'settings-preservation'
        report['server_final'] = snapshot(ssh, account, since)
        helpers.require(initial['server_config_sha256'] == report['server_final']['server_config_sha256'],
                        'Server configuration changed during this measurement')
        after_store = helpers.ledger(sftp)
        registry = helpers.private_json(sftp, helpers.OWNER + '/users.private.json')
        records = {'admin': next(a for a in accounts if a['id'] == 'admin')['record'],
                   **{a['id']: a for a in registry['users']}}
        after_hashes = [helpers.settings_hash(helpers.private_json(sftp, a['state_path']),
                                             records.get(a['id']), after_store) for a in accounts]
        report['all_settings_after_sha256'] = helpers.fingerprint(after_hashes)
        report['all_settings_preserved'] = all(new == old['settings_hash'] for new, old in zip(after_hashes, accounts))
        report['normal_monthly_ledger_delta'] = {key: helpers.month_totals(after_store, account['id'], month)[key]
            - helpers.month_totals(before_store, account['id'], month)[key] for key in ('up_bytes', 'down_bytes')}
        observations = [a['first_request_after_idle'] for a in report['idle_observations']]
        report['measurement_completed'] = True
        report['measurement_valid'] = (all(a['success'] for a in fresh + warm + observations)
            and all(p['completed_full_blocks'] > 0 and p['sufficient_load_coverage']
                    for p in report['phases'] if p['name'] != 'idle'))
        report['success'] = report['measurement_valid'] and report['all_settings_preserved']
        return report
    except Exception as error:
        report.update(failure_stage=stage, error_type=type(error).__name__)
        if isinstance(error, SnapshotFailure):
            report['safe_error_detail'] = error.safe_detail
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
            helpers.require(directory.resolve().parent == base.TEMP_ROOT.resolve() and not directory.is_symlink()
                            and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe private cleanup path')
            if directory.exists():
                shutil.rmtree(str(directory))
        except Exception as error:
            report['cleanup_errors'].append('directory:' + type(error).__name__)
        report['own_mihomo_processes_terminated'] = all(c.process is None or c.process.poll() is not None for c in clients)
        report['own_curl_processes_terminated'] = all(p.poll() is not None for c in clients for p in c.all_children)
        report['temporary_private_files_removed'] = not directory.exists()
        report['finished_at'] = base.utc()
        report['total_wall_seconds'] = round(time.monotonic() - clock_start, 3)
        if report['cleanup_errors'] or not all(report[k] for k in ('own_mihomo_processes_terminated',
                'own_curl_processes_terminated', 'temporary_private_files_removed')):
            report['success'] = False
        if report_path is not None:
            report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--mode', choices=('idle', 'profile'))
    group.add_argument('--check-local', action='store_true')
    parser.add_argument('--label', type=lambda value: value if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value)
                        else parser.error('label must be simple lowercase ASCII'))
    parser.add_argument('--client-profile', choices=PROFILES, default='standard')
    parser.add_argument('--expected-server-profile', choices=PROFILES)
    parser.add_argument('--account-port', type=int, choices=(443, 2443), default=443)
    parser.add_argument('--load-seconds', type=int, choices=(12, 16), default=16)
    result = run(parser.parse_args())
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result.get('success') else 1)
