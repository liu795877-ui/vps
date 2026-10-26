"""Verify current public AUTO nodes using a separate loopback-only Mihomo.

Reads fresh authenticated state/profile/traffic data and probes public ports on
the physical WLAN. There is no SSH fallback and no use of stale port evidence.
Only this script's client process, selection and private temp files are changed.
No credentials, UUIDs, capabilities or YAML are written into the public report.
"""

import argparse
import base64
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener
import uuid

import yaml

import frontend_motion_access as live
from ssh_access import FOLDER
from update_routing_url import login_sessions, logout_sessions


BINARY = Path('C:/Users/LENOVO/.cockpit_tools/proxy-engine/release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe')
CURL = 'C:/Windows/System32/curl.exe'
REPORT = FOLDER / 'operations-clients-verification.json'
TEMP_ROOT = FOLDER / 'operations-client-validation'
AUTO_NAME = 'AUTO · 网页切换'


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def configuration(nodes, proxy_port, controller_port, secret):
    return {'mixed-port': proxy_port, 'port': 0, 'socks-port': 0,
            'allow-lan': False, 'bind-address': '127.0.0.1', 'ipv6': False,
            'tun': {'enable': False}, 'interface-name': 'WLAN',
            'log-level': 'error', 'mode': 'rule',
            'external-controller': '127.0.0.1:' + str(controller_port), 'secret': secret,
            'profile': {'store-selected': False, 'store-fake-ip': False},
            'proxies': copy.deepcopy(nodes),
            'proxy-groups': [{'name': 'ACCEPTANCE', 'type': 'select',
                              'proxies': [node['name'] for node in nodes]}],
            'rules': ['MATCH,ACCEPTANCE']}


def cleanup_directory(directory):
    live.require(not directory.is_symlink() and directory.resolve().parent == TEMP_ROOT.resolve()
                 and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe client cleanup directory')
    if directory.exists():
        shutil.rmtree(str(directory))


def get_json(session, path):
    status, _, body = live.request('GET', path, headers={'Cookie': session['cookie']})
    live.require(status == 200, 'A read-only production API did not respond successfully')
    try:
        result = json.loads(body)
    except ValueError:
        raise RuntimeError('A production API returned invalid JSON') from None
    live.require(isinstance(result, dict), 'A production API returned an invalid structure')
    return result


def settings_hash(state, traffic, subscription):
    fields = ('server_ip', 'server_port', 'active_target', 'active', 'exits',
              'domains', 'direct_domains', 'routing_mode', 'updated')
    payload = {key: state.get(key) for key in fields}
    payload['limits'] = {key: traffic.get(key) for key in ('quota_bytes', 'rate_bps')}
    payload['subscription'] = subscription
    return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()


def expected_ip(state):
    if state.get('active_target') == 'server':
        value = live.IP
    else:
        active, health = state.get('active') or {}, state.get('health') or {}
        value = active.get('observed_ip')
        if (health.get('status') == 'healthy' and health.get('checked_exit_id') == active.get('id')
                and health.get('observed_ip')):
            value = health['observed_ip']
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise RuntimeError('The applied current exit has no verified IP to compare') from None
    live.require(address.is_global, 'The applied exit does not have a public IP')
    return str(address)


def collect_accounts(sessions):
    accounts = []
    for identity, session in sessions.items():
        state = get_json(session, 'api/state')
        traffic = get_json(session, 'api/traffic')
        subscription = get_json(session, 'api/subscription')
        live.require(state.get('user', {}).get('id') == identity and state.get('server_ip') == live.IP,
                     'A current account session identifies another server or account')
        live.require(not (state.get('job') or {}).get('status') == 'running',
                     'A current account is changing its exit; acceptance must wait')
        status, _, profile_bytes = live.request('GET', 'api/profile', headers={'Cookie': session['cookie']})
        live.require(status == 200, 'A current account profile could not be read')
        try:
            profile = yaml.safe_load(profile_bytes)
            nodes = [node for node in profile['proxies'] if node.get('name') == AUTO_NAME]
        except (ValueError, TypeError, KeyError, yaml.YAMLError):
            raise RuntimeError('A current profile could not be parsed') from None
        live.require(len(nodes) == 1, 'A profile does not contain exactly one AUTO node')
        node = copy.deepcopy(nodes[0])
        live.require(node.get('type') == 'vless' and node.get('server') == live.IP
                     and node.get('port') == state.get('server_port')
                     and node.get('port') in (443, 1443, 2443), 'A current AUTO node targets an unexpected entrance')
        try:
            uuid.UUID(node['uuid'])
        except (ValueError, TypeError, KeyError):
            raise RuntimeError('An AUTO proxy identity is invalid') from None
        profile_hash = hashlib.sha256(profile_bytes).hexdigest()
        live.require(subscription.get('hash') == profile_hash and subscription.get('download_ready') is True,
                     'Server profile metadata does not match the downloaded content')
        accounts.append({'session': session, 'node': node, 'port': node['port'],
                         'expected_ip': expected_ip(state), 'before_traffic': traffic,
                         'settings_hash': settings_hash(state, traffic, subscription),
                         'profile_hash': profile_hash, 'profile_bytes': len(profile_bytes)})
    accounts.sort(key=lambda account: account['port'])
    live.require([account['port'] for account in accounts] == [443, 1443, 2443],
                 'Fresh enabled account inventory must contain all three entrances')
    live.require(len({account['node']['uuid'] for account in accounts}) == 3,
                 'Current account proxy identities are shared')
    return accounts


def syntax_check(directory, candidate, log):
    checked = subprocess.run([str(BINARY), '-t', '-d', str(directory), '-f', str(candidate)],
                             stdout=log, stderr=subprocess.STDOUT, timeout=30, creationflags=live.NO_WINDOW)
    live.require(checked.returncode == 0, 'The official Mihomo core rejected the AUTO test configuration')


def main(local_only=False):
    report = {'success': False, 'checked_at': datetime.now(timezone.utc).isoformat(),
              'profile_read_count': 0, 'public_ports': [], 'samples': [],
              'tun_disabled': True, 'physical_wlan': True, 'local_client_only': True,
              'configuration_changes': 0, 'credential_changes': 0}
    directory = TEMP_ROOT / secrets.token_hex(8)
    process = None
    sessions = {}
    phase = 'local-core'
    observations = {}
    try:
        live.require(BINARY.is_file() and not BINARY.is_symlink(), 'The isolated Mihomo binary is unavailable')
        live.require(not TEMP_ROOT.is_symlink(), 'The isolated client parent directory is unsafe')
        directory.mkdir(parents=True, exist_ok=False)
        report['core_sha256'] = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        proxy_port, control_port = free_port(), free_port()
        while proxy_port == control_port:
            control_port = free_port()
        secret = secrets.token_urlsafe(32)
        if local_only:
            public = base64.urlsafe_b64encode(bytes(range(32))).decode('ascii').rstrip('=')
            nodes = [{'name': 'synthetic', 'type': 'vless', 'server': live.IP, 'port': 443,
                      'uuid': str(uuid.uuid4()), 'tls': True, 'udp': False,
                      'servername': 'www.microsoft.com', 'client-fingerprint': 'chrome',
                      'flow': 'xtls-rprx-vision', 'reality-opts': {'public-key': public, 'short-id': '0123456789abcdef'}}]
            candidate = directory / 'synthetic.private.yaml'
            candidate.write_text(yaml.safe_dump(configuration(nodes, proxy_port, control_port, secret),
                                                allow_unicode=True, sort_keys=False), encoding='utf-8')
            with (directory / 'syntax.private.log').open('w', encoding='utf-8') as log:
                syntax_check(directory, candidate, log)
            report.update(success=True, local_syntax_only=True, server_requests=0)
            return report
        phase = 'current-account-reads'
        sessions = login_sessions()
        accounts = collect_accounts(sessions)
        report['profile_read_count'] = len(accounts)
        phase = 'physical-wlan-ports'
        for account in accounts:
            try:
                with live.physical_socket(account['port'], timeout=3):
                    account['reachable'] = True
            except OSError:
                account['reachable'] = False
            report['public_ports'].append({'port': account['port'], 'tcp_reachable': account['reachable']})
        nodes = []
        for account in accounts:
            node = copy.deepcopy(account['node'])
            node['name'] = 'entrance-' + str(account['port'])
            account['test_name'] = node['name']
            nodes.append(node)
        for destination, identity_source in [(accounts[1], accounts[2]), (accounts[2], accounts[1])]:
            wrong = copy.deepcopy(destination['node'])
            wrong.update(name='cross-' + str(destination['port']), uuid=identity_source['node']['uuid'])
            nodes.append(wrong)
        candidate = directory / 'current-auto.private.yaml'
        candidate.write_text(yaml.safe_dump(configuration(nodes, proxy_port, control_port, secret),
                                            allow_unicode=True, sort_keys=False), encoding='utf-8')
        phase = 'isolated-core'
        with (directory / 'client.private.log').open('w', encoding='utf-8') as log:
            syntax_check(directory, candidate, log)
            report['official_auto_syntax_accepted'] = True
            process = subprocess.Popen([str(BINARY), '-d', str(directory), '-f', str(candidate)],
                                       stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                       creationflags=live.NO_WINDOW)
            opener = build_opener(ProxyHandler({}))
            controller = 'http://127.0.0.1:' + str(control_port)

            def api(path, method='GET', data=None):
                query = Request(controller + path, json.dumps(data).encode('utf-8') if data is not None else None,
                                {'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'}, method=method)
                with opener.open(query, timeout=4) as response:
                    payload = response.read()
                    return json.loads(payload) if payload else None

            deadline = time.monotonic() + 20
            while True:
                live.require(process.poll() is None, 'The isolated Mihomo process exited')
                try:
                    api('/version')
                    break
                except OSError:
                    live.require(time.monotonic() < deadline, 'The isolated client controller did not start')
                    time.sleep(.2)

            def observe(name, positive):
                api('/connections', 'DELETE')
                api('/proxies/' + quote('ACCEPTANCE', safe=''), 'PUT', {'name': name})
                outcome = None
                for attempt in range(3 if positive else 1):
                    outcome = subprocess.run([CURL, '--proxy', 'socks5h://127.0.0.1:' + str(proxy_port),
                        '--noproxy', '', '--connect-timeout', '5', '--max-time', '12' if positive else '8',
                        '--silent', '--show-error', 'https://api.ipify.org'],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=16, creationflags=live.NO_WINDOW)
                    if outcome.returncode == 0 or not positive:
                        break
                    time.sleep(.2)
                error_text = outcome.stderr.decode('utf-8', 'replace').lower()
                error_category = next((label for needle, label in (
                    ('failed to connect', 'connect-failed'), ('timed out', 'timed-out'),
                    ('connection reset', 'connection-reset'), ('ssl', 'tls-failed'),
                    ('socks', 'socks-failed'), ('empty reply', 'empty-reply')) if needle in error_text),
                    'none' if outcome.returncode == 0 else 'other')
                observations[name] = {'curl_exit_code': outcome.returncode, 'curl_error_category': error_category}
                if outcome.returncode != 0:
                    return None
                try:
                    observed = ipaddress.ip_address(outcome.stdout.decode('ascii').strip())
                except (ValueError, UnicodeError):
                    raise RuntimeError('The external IP service returned an invalid response') from None
                live.require(observed.is_global, 'The real proxy response is not a public IP')
                return str(observed)

            phase = 'real-auto-egress'
            for account in accounts:
                account['verified'] = False
                sample = {'port': account['port'], 'profile_sha256': account['profile_hash'],
                          'profile_bytes': account['profile_bytes'], 'expected_ip': account['expected_ip'],
                          'public_auto_verified': False, 'isolation_checked': False}
                report['samples'].append(sample)
                account['sample'] = sample
                if not account['reachable']:
                    continue
                observed = observe(account['test_name'], True)
                sample.update(observations[account['test_name']])
                sample['observed_ip'] = observed
                account['verified'] = observed == account['expected_ip']
                sample['public_auto_verified'] = account['verified']
            phase = 'member-isolation'
            for account in accounts[1:]:
                other = next(item for item in accounts[1:] if item is not account)
                if not account['verified'] or not other['verified']:
                    continue
                rejected = observe('cross-' + str(account['port']), False) is None
                good_after = observe(account['test_name'], True) == account['expected_ip']
                account['sample'].update(isolation_checked=True, other_member_uuid_rejected=rejected,
                                         valid_identity_after_negative=good_after)
            phase = 'real-traffic-samples'
            pending = [account for account in accounts if account['verified']]
            sample_deadline = time.monotonic() + 30
            while pending and time.monotonic() < sample_deadline:
                for account in list(pending):
                    traffic = get_json(account['session'], 'api/traffic')
                    before = account['before_traffic']
                    up = traffic.get('up_bytes', 0) - before.get('up_bytes', 0)
                    down = traffic.get('down_bytes', 0) - before.get('down_bytes', 0)
                    if traffic.get('available') and up > 0 and down > 0:
                        account['sample'].update(real_traffic_increment=True, uplink_delta_bytes=up,
                                                downlink_delta_bytes=down)
                        pending.remove(account)
                if pending:
                    time.sleep(min(2, max(0, sample_deadline - time.monotonic())))
            for account in pending:
                account['sample']['real_traffic_increment'] = False
            phase = 'read-only-preservation'
            for account in accounts:
                state = get_json(account['session'], 'api/state')
                traffic = get_json(account['session'], 'api/traffic')
                subscription = get_json(account['session'], 'api/subscription')
                account['sample']['settings_preserved'] = settings_hash(state, traffic, subscription) == account['settings_hash']
            report.update(positive_count=sum(bool(sample['public_auto_verified']) for sample in report['samples']),
                          unreachable_port_count=sum(not item['tcp_reachable'] for item in report['public_ports']),
                          isolation_verified=all(account['sample'].get('other_member_uuid_rejected')
                              and account['sample'].get('valid_identity_after_negative') for account in accounts[1:]),
                          all_settings_preserved=all(account['sample']['settings_preserved'] for account in accounts),
                          all_traffic_incremented=all(account['sample'].get('real_traffic_increment') for account in accounts))
            report['success'] = (report['positive_count'] == 3 and report['isolation_verified']
                                 and report['all_settings_preserved'] and report['all_traffic_incremented'])
            report['completed'] = True
        core_log = (directory / 'client.private.log').read_text(encoding='utf-8', errors='replace').lower()
        report['core_error_categories'] = [label for needle, label in (
            ('network is unreachable', 'network-unreachable'), ('no such host', 'dns-failed'),
            ('connection refused', 'connection-refused'), ('i/o timeout', 'io-timeout'),
            ('handshake', 'handshake-error'), ('certificate', 'certificate-error'),
            ('unknown interface', 'interface-error'), ('invalid argument', 'argument-error')) if needle in core_log]
        return report
    except Exception as error:
        # Exception messages and core/curl logs can contain private URLs or
        # config lines. Persist only a fixed phase and the exception class.
        report.update(failed=True, failure_phase=phase, error_type=type(error).__name__)
        return report
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        logout_sessions(sessions)
        cleanup_directory(directory)
        report['temporary_private_files_removed'] = not directory.exists()
        report['own_client_process_terminated'] = process is None or process.poll() is not None
        if not local_only:
            REPORT.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-local', action='store_true')
    args = parser.parse_args()
    result = main(args.check_local)
    print(json.dumps(result))
    sys.exit(0 if result.get('success') else 1)
