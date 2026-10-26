"""Fast.com official targets and bounded sequential proxy comparison.

--mode targets fetches only Fast's frontend, app JS and target API via existing
FlClash SOCKS 7890. --mode compare additionally measures, strictly in sequence,
existing FlClash, fresh current HY2, and fresh current VLESS. Each path downloads
at most four 16 MiB blocks for at most 12 seconds. Signed URLs and frontend/API
tokens stay in memory and never appear in the report or saved files.
--active-only measures just the existing FlClash path in compare mode.
No active FlClash/server profile, exit, DNS, account or route is changed.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

import benchmark_hy2_latency as base
import verify_hy2_clients as helpers


ACTIVE_PROXY_PORT = 7890
MAX_TARGETS = 4
MAX_BLOCK_BYTES = 16777216
MAX_PATH_SECONDS = 12
MAX_DISCOVERY_BYTES = 1048576
MARKER = b'FAST_SAFE_METRICS='
FORMAT = '{"http_code":%{http_code},"size_download":%{size_download},"time_connect":%{time_connect},"time_appconnect":%{time_appconnect},"time_pretransfer":%{time_pretransfer},"time_starttransfer":%{time_starttransfer},"time_total":%{time_total}}'


class SafeFailure(RuntimeError):
    def __init__(self, stage, category):
        super().__init__('Fast diagnostic failed')
        self.safe_detail = {'stage': stage, 'category': category}


def error_category(raw):
    text = raw.decode('utf-8', 'replace').lower()
    return next((label for needle, label in [('timed out', 'timeout'), ('resolve', 'dns'),
        ('socks', 'socks'), ('ssl', 'tls'), ('certificate', 'tls'), ('reset', 'reset'),
        ('maximum file size', 'size-cap'), ('failed to connect', 'connect')] if needle in text), 'request')


def curl_args(port, seconds, byte_cap):
    return [helpers.CURL, '--proxy', 'socks5h://127.0.0.1:' + str(port), '--noproxy', '',
        '--connect-timeout', str(min(5, seconds)), '--max-time', str(seconds), '--max-filesize', str(byte_cap),
        '--ssl-no-revoke', '--silent', '--show-error', '--user-agent', 'Mozilla/5.0 FastDiagnostic',
        '--write-out', '%{stderr}' + MARKER.decode('ascii') + FORMAT]


def parse_metrics(error):
    try:
        raw, suffix = error.rsplit(MARKER, 1)
        return json.loads(suffix.decode('ascii')), raw
    except (ValueError, UnicodeError):
        return {}, error


def fetch(url, stage):
    result = subprocess.run(curl_args(ACTIVE_PROXY_PORT, 15, MAX_DISCOVERY_BYTES) + [url],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=19, creationflags=base.live.NO_WINDOW)
    metrics, error = parse_metrics(result.stderr)
    if result.returncode or metrics.get('http_code') != 200 or len(result.stdout) > MAX_DISCOVERY_BYTES:
        raise SafeFailure(stage, error_category(error) if result.returncode else 'http-' + str(metrics.get('http_code')))
    return result.stdout, metrics


def token_candidates(text):
    patterns = [r'\btoken\s*[:=]\s*["\']([A-Za-z0-9_-]{16,256})["\']',
                r'\btoken=([A-Za-z0-9_-]{16,256})']
    values = []
    for pattern in patterns:
        values.extend(re.findall(pattern, text))
    # The official frontend sometimes stores the API token as a minified
    # parameter named fastToken; this is still discovered from current JS.
    values.extend(re.findall(r'\bfastToken\s*[:=]\s*["\']([A-Za-z0-9_-]{16,256})["\']', text))
    return list(dict.fromkeys(values))[:8]


def public_target(item):
    location = item.get('location') if isinstance(item.get('location'), dict) else {}
    return {'hostname': urlsplit(item['url']).hostname,
            'region': {key: str(location[key])[:128] for key in ('city', 'country') if key in location}}


def discover():
    html, html_metrics = fetch('https://fast.com/', 'fast-frontend')
    text = html.decode('utf-8', 'replace')
    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text, flags=re.I)
    scripts = [urljoin('https://fast.com/', item) for item in scripts]
    scripts = [item for item in scripts if urlsplit(item).hostname == 'fast.com']
    scripts.sort(key=lambda item: ('app' not in urlsplit(item).path, item))
    discovery = {'frontend_bytes': len(html), 'frontend_http_code': html_metrics.get('http_code'),
                 'js_bytes': 0, 'js_files_fetched': 0, 'token_discovered': False,
                 'target_api_attempts': 0, 'download_payload_bytes': 0, 'proxy_port': ACTIVE_PROXY_PORT}
    candidates = token_candidates(text)
    for source in scripts[:6]:
        script, _ = fetch(source, 'fast-app-js')
        discovery['js_bytes'] += len(script)
        discovery['js_files_fetched'] += 1
        candidates.extend(token_candidates(script.decode('utf-8', 'replace')))
        if candidates:
            break
    candidates = list(dict.fromkeys(candidates))[:8]
    discovery['token_discovered'] = bool(candidates)
    if not candidates:
        raise SafeFailure('fast-token-discovery', 'no-current-frontend-token')
    for token in candidates:
        discovery['target_api_attempts'] += 1
        api = 'https://api.fast.com/netflix/speedtest/v2?' + urlencode(
            {'https': 'true', 'token': token, 'urlCount': MAX_TARGETS})
        try:
            payload, _ = fetch(api, 'fast-target-api')
            data = json.loads(payload)
        except (SafeFailure, ValueError):
            continue
        targets = data.get('targets', []) if isinstance(data, dict) else []
        if not targets:
            continue
        valid = []
        for item in targets:
            if not isinstance(item, dict) or not isinstance(item.get('url'), str):
                continue
            address = urlsplit(item['url'])
            hostname = address.hostname or ''
            if (address.scheme == 'https' and hostname.endswith('.nflxvideo.net') and
                    not address.username and not address.password and address.port in (None, 443)):
                valid.append(item)
        if len(valid) < MAX_TARGETS:
            continue
        client = data.get('client', {})
        try:
            client_ip = str(ipaddress.ip_address(client.get('ip')))
        except (ValueError, TypeError):
            client_ip = None
        location = client.get('location') if isinstance(client.get('location'), dict) else {}
        discovery.update(api_payload_bytes=len(payload), client_ip=client_ip,
            client_region={key: str(location[key])[:128] for key in ('city', 'country') if key in location},
            targets=[public_target(item) for item in valid[:MAX_TARGETS]], target_count=MAX_TARGETS,
            signed_urls_saved=False, tokens_saved=False)
        return valid[:MAX_TARGETS], discovery
    raise SafeFailure('fast-target-api', 'no-four-valid-official-targets')


def bounded_url(url):
    address = urlsplit(url)
    # Current app JS normalizes targets[ind].url with
    # url.replace(/speedtest/, "speedtest/range/") then replaces /range/ with
    # /range/0-N. The current API gives /speedtest, not a prebuilt range.
    replacement = '/range/0-' + str(MAX_BLOCK_BYTES - 1)
    if address.path.rstrip('/') == '/speedtest':
        path = '/speedtest' + replacement
    elif address.path == '/speedtest/range/':
        path = '/speedtest' + replacement
    else:
        path, matches = re.subn(r'/range/\d+-\d+(?=/|$)', replacement, address.path)
        if matches != 1:
            raise SafeFailure('fast-target-path', 'unexpected-official-range-path')
    return urlunsplit((address.scheme, address.netloc, path, address.query, ''))


def download_one(port, target, index, own_processes, path_deadline):
    # Range is encoded as the official endpoint path and repeated as HTTP Range.
    # curl enforces response size even if a peer ignores Range. The reader adds
    # a second bounded stop and retains no payload data.
    url = bounded_url(target['url'])
    started = time.monotonic()
    remaining = max(.001, path_deadline - started)
    process = subprocess.Popen(curl_args(port, round(remaining, 3), MAX_BLOCK_BYTES) +
        ['--range', '0-' + str(MAX_BLOCK_BYTES - 1), url], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=base.live.NO_WINDOW)
    own_processes.append(process)
    actual = 0
    try:
        while True:
            chunk = process.stdout.read(min(65536, MAX_BLOCK_BYTES - actual + 1))
            if not chunk:
                break
            actual += len(chunk)
            if actual > MAX_BLOCK_BYTES:
                process.kill()
                break
        _, error = process.communicate(timeout=4)
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=4)
        raise
    ended = time.monotonic()
    metrics, raw_error = parse_metrics(error)
    code = process.returncode
    http = metrics.get('http_code')
    return {'target': index + 1, **public_target(target), 'curl_exit_code': code, 'http_code': http,
        'actual_download_bytes': min(actual, MAX_BLOCK_BYTES), 'curl_reported_download_bytes': metrics.get('size_download'),
        'maximum_download_bytes': MAX_BLOCK_BYTES, 'wall_seconds': round(ended - started, 4),
        'curl_total_seconds': metrics.get('time_total'),
        'ttfb_ms': round(metrics['time_starttransfer'] * 1000, 3) if isinstance(metrics.get('time_starttransfer'), (int, float)) else None,
        'tls_ready_ms': round(metrics['time_appconnect'] * 1000, 3) if isinstance(metrics.get('time_appconnect'), (int, float)) else None,
        'completed_full_block': code == 0 and actual == MAX_BLOCK_BYTES and http in (200, 206),
        'bounded_partial': code in (28, 63) and actual > 0 and http in (200, 206),
        'response_payload_received': actual > 0 and http in (200, 206),
        'error_category': 'none' if code == 0 else error_category(raw_error)}


def path_measurement(label, port, targets, own_processes):
    base.emit('phase-start', label, parallel_downloads=MAX_TARGETS,
              maximum_payload_bytes=MAX_TARGETS * MAX_BLOCK_BYTES, maximum_seconds=MAX_PATH_SECONDS)
    started = time.monotonic()
    deadline = started + MAX_PATH_SECONDS
    with ThreadPoolExecutor(max_workers=MAX_TARGETS) as pool:
        jobs = [pool.submit(download_one, port, item, index, own_processes, deadline) for index, item in enumerate(targets)]
        rows = [job.result() for job in jobs]
    wall = time.monotonic() - started
    actual = sum(row['actual_download_bytes'] for row in rows)
    result = {'label': label, 'proxy_port': port, 'strict_sequential_path': True, 'parallel_requests': MAX_TARGETS,
        'actual_download_bytes': actual, 'maximum_payload_bytes': MAX_TARGETS * MAX_BLOCK_BYTES,
        'elapsed_seconds': round(wall, 4), 'observed_download_mbps_including_startup': round(actual * 8 / wall / 1e6, 3),
        'completed_full_blocks': sum(row['completed_full_block'] for row in rows),
        'payload_successes': sum(row['response_payload_received'] for row in rows),
        'bounded_partials': sum(row['bounded_partial'] for row in rows), 'requests': rows,
        'success': all(row['response_payload_received'] for row in rows),
        'measurement_scope': 'bounded Fast official HTTP requests; not an unrestricted browser Fast score'}
    base.emit('phase-end', label, bytes=actual, mbps=result['observed_download_mbps_including_startup'],
              payload_successes=result['payload_successes'])
    return result


def run(args):
    paths = [('active-flclash', None)]
    if not getattr(args, 'active_only', False):
        paths += [('current-admin-hy2', 'hy2'), ('current-admin-vless', 'xray')]
    payload_cap = MAX_BLOCK_BYTES * MAX_TARGETS * len(paths)
    directory = base.TEMP_ROOT / secrets.token_hex(8)
    own_processes, clients, ssh, sftp = [], [], None, None
    report = {'success': False, 'mode': args.mode or 'local-check', 'label': args.label,
        'started_at': base.utc(), 'configuration_changes': 0, 'credential_changes': 0,
        'exit_changes': 0, 'signed_urls_saved': False, 'tokens_saved': False, 'paths': [], 'cleanup_errors': []}
    report_path = helpers.FOLDER / ('fast-' + ('targets' if args.mode == 'targets' else args.label) + '.json') if args.mode else None
    started = time.monotonic()
    stage = 'private-local-gate'
    try:
        helpers.require(not base.TEMP_ROOT.is_symlink(), 'Unsafe private parent')
        report['private_directory_acl'] = base.make_private(directory)
        report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['method'] = {'parallel_downloads': MAX_TARGETS, 'maximum_payload_per_path': MAX_TARGETS * MAX_BLOCK_BYTES,
            'maximum_request_seconds': MAX_PATH_SECONDS, 'block_bytes': MAX_BLOCK_BYTES,
            'path_order': [label for label, unused_source in paths],
            'path_count': len(paths), 'maximum_payload_all_paths': payload_cap,
            'path_scope': 'existing FlClash only' if getattr(args, 'active_only', False) else 'existing FlClash and isolated current HY2/VLESS',
            'same_signed_targets_across_paths': True, 'active_flclash_port': ACTIVE_PROXY_PORT,
            'all_parallel_downloads_share_12_second_deadline': True,
            'no_controller_delete_connections': True, 'no_configuration_changes': True,
            'range_in_official_path_and_http_header': True, 'payload_discarded_without_files': True,
            'range_assembly': 'current official JS: /speedtest -> /speedtest/range/0-N, query unchanged'}
        report['method_sha256'] = helpers.fingerprint(report['method'])
        if args.check_local:
            value = bounded_url('https://ipv4-c001-test.1.nflxvideo.net/speedtest/range/0-0?synthetic=only')
            helpers.require('/range/0-16777215?' in value and value.endswith('synthetic=only'), 'Range contract failed')
            for path in ('/speedtest', '/speedtest/', '/speedtest/range/'):
                value = bounded_url('https://ipv4-c001-test.1.nflxvideo.net' + path + '?synthetic=only')
                helpers.require(urlsplit(value).path == '/speedtest/range/0-16777215'
                                and value.endswith('synthetic=only'), 'Current official target normalization failed')
            helpers.require(token_candidates('a={token:"synthetic000000000000000000token"}') == ['synthetic000000000000000000token'],
                            'Token discovery fixture failed')
            test_node = helpers.synthetic_nodes()[0]
            client = base.BenchClient(directory / 'synthetic', test_node, started)
            clients.append(client)
            client.syntax()
            report.update(success=True, offline_check=True, server_requests=0)
            return report
        stage = 'fast-target-discovery'
        targets, discovery = discover()
        # Validate the path before any traffic-bearing phase.
        for target in targets:
            bounded_url(target['url'])
        discovery['official_range_paths_validated_without_payload'] = True
        report['discovery'] = discovery
        base.emit('phase-end', 'fast-target-discovery', client_ip=discovery['client_ip'],
                  target_count=len(targets), download_payload_bytes=0)
        if args.mode == 'targets':
            report['success'] = True
            return report
        stage = 'current-private-profile-reads'
        ssh = helpers.connect()
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(20)
        accounts, store = helpers.collect_accounts(sftp)
        account = next(item for item in accounts if item['id'] == 'admin')
        state = helpers.private_json(sftp, account['state_path'])
        helpers.require(state.get('active_id') in (None, 'server') and account['expected_ip'] == base.live.IP,
                        'Current admin exit must remain the server exit')
        helpers.require(discovery['client_ip'] == base.live.IP, 'Active FlClash Fast target API uses an unexpected exit')
        report['current_server_exit_ip'] = account['expected_ip']
        report['profile_sha256'] = account['profile_sha256']
        report['core_sha256'] = hashlib.sha256(helpers.BINARY.read_bytes()).hexdigest()
        report['account_settings_sha256'] = account['settings_hash']
        quota = store.get('users', {}).get('admin', {}).get('quota_bytes', 0)
        month = time.strftime('%Y-%m', time.gmtime())
        used = sum(helpers.month_totals(store, 'admin', month).values())
        helpers.require(not quota or quota - used > payload_cap + 16777216,
                        'Normal quota remaining is insufficient for bounded comparison')
        for label, source in paths:
            stage = label
            client = None
            if source:
                client = base.BenchClient(directory / label, account['nodes'][source], started)
                clients.append(client)
                client.start(time.monotonic() + 35)
                port = client.proxy_port
            else:
                port = ACTIVE_PROXY_PORT
            before = {kind: helpers.native_snapshot(ssh, account, kind) for kind in ('hy2', 'xray')}
            measured = path_measurement(label, port, targets, own_processes)
            after = {kind: helpers.native_snapshot(ssh, account, kind) for kind in ('hy2', 'xray')}
            measured['native_account_counter_delta'] = {kind: helpers.counter_delta(before[kind], after[kind]) for kind in before}
            measured['native_counter_scope'] = 'all admin account traffic during this bounded path, including unrelated activity'
            report['paths'].append(measured)
            if client is not None:
                client.close()
        stage = 'settings-preservation'
        after_store = helpers.ledger(sftp)
        after_state = helpers.private_json(sftp, account['state_path'])
        report['account_settings_preserved'] = helpers.settings_hash(after_state, account['record'], after_store) == account['settings_hash']
        report['success'] = report['account_settings_preserved'] and all(p['success'] for p in report['paths'])
        return report
    except Exception as error:
        report.update(failure_stage=stage, error_type=type(error).__name__)
        if isinstance(error, SafeFailure):
            report['safe_error_detail'] = error.safe_detail
        return report
    finally:
        for process in own_processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=4)
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
        report['own_curl_processes_terminated'] = all(p.poll() is not None for p in own_processes)
        report['temporary_private_files_removed'] = not directory.exists()
        report['finished_at'] = base.utc()
        report['total_wall_seconds'] = round(time.monotonic() - started, 3)
        if report['cleanup_errors'] or not all(report[k] for k in ('own_mihomo_processes_terminated',
                'own_curl_processes_terminated', 'temporary_private_files_removed')):
            report['success'] = False
        if report_path:
            report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--mode', choices=('targets', 'compare'))
    group.add_argument('--check-local', action='store_true')
    parser.add_argument('--active-only', action='store_true',
                        help='Measure only the existing FlClash path; compare mode or local check.')
    parser.add_argument('--label', default='regression', type=lambda value: value if
                        re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value) else parser.error('Simple lowercase ASCII label required'))
    args = parser.parse_args()
    if args.active_only and args.mode == 'targets':
        parser.error('--active-only requires --mode compare or --check-local')
    result = run(args)
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result.get('success') else 1)
