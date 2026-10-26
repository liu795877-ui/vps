"""Read-only acceptance of three fresh HY2 and REALITY account profiles.

--check-local validates synthetic profiles with the installed official Mihomo;
it never connects to the VPS. --run reads current private profiles over the
existing physical-WLAN SSH transport, starts one loopback-only isolated client,
and performs bounded test transfers. It never changes a web exit, application
configuration, credential, firewall, active FlClash process, or system routing.
Public reports contain no passwords, UUIDs, rule URLs, or source email labels.
"""

import argparse
import ast
import base64
import copy
import contextlib
from datetime import datetime, timezone
import hashlib
import ipaddress
import io
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener
import uuid
from unittest.mock import patch

import yaml

import frontend_motion_access as live
from ssh_access import FOLDER, connect, execute


BINARY = Path('C:/Users/LENOVO/.cockpit_tools/proxy-engine/release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe')
CURL = 'C:/Windows/System32/curl.exe'
TEMP_ROOT = FOLDER / 'hy2-client-validation'
REPORT = FOLDER / 'hy2-clients-verification.json'
OWNER = '/var/lib/vps-panel'
NAMES = {'hy2': 'HY2 · 网页切换', 'xray': 'REALITY · TCP兼容'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()


def private_json(sftp, path):
    # Contents remain in memory; do not copy production registry/profile files.
    with sftp.open(path, 'rb') as stream:
        value = json.loads(stream.read().decode('utf-8'))
    require(isinstance(value, dict), 'A private read returned an invalid structure')
    return value


def ledger(sftp):
    return private_json(sftp, OWNER + '/traffic.private.json')


def month_totals(store, identity, month):
    user = store.get('users', {}).get(identity, {})
    totals = user.get('months', {}).get(month, {})
    return {key: totals.get(key, 0) for key in ('up_bytes', 'down_bytes')}


def source_totals(store, identity, source):
    value = store.get('users', {}).get(identity, {}).get('sources', {}).get(source, {})
    counters = value.get('counters', {})
    return {'up_bytes': sum(amount for key, amount in counters.items() if key.endswith('>>>uplink')),
            'down_bytes': sum(amount for key, amount in counters.items() if key.endswith('>>>downlink')),
            'epoch': value.get('epoch')}


def source_delta(before, after):
    # An integration release can leave a baseline from the old process until
    # the next normal sampler pass; its new counter is a fresh lifetime value.
    return {key: (after[key] if before['epoch'] != after['epoch'] else after[key] - before[key])
            for key in ('up_bytes', 'down_bytes')}


def settings_hash(state, record, store):
    # Profile and account metadata include every proxy credential; hash only.
    user = store.get('users', {}).get(record['id'], {})
    return fingerprint({'state': state, 'record': record,
                        'limits': {key: user.get(key, 0) for key in ('quota_bytes', 'rate_bps')}})


def expected_ip(state, health):
    active_id = state.get('active_id')
    if active_id in (None, 'server'):
        value = live.IP
    else:
        active = next((item for item in state.get('applied_exits', []) if item['id'] == active_id), {})
        value = active.get('observed_ip')
        if (health.get('status') == 'healthy' and health.get('checked_exit_id') == active_id
                and health.get('observed_ip')):
            value = health['observed_ip']
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise RuntimeError('The currently applied exit has no verified public IP') from None
    require(address.is_global, 'The currently applied exit is not public')
    return str(address)


def validate_nodes(state, integration, identity, port):
    try:
        profile = yaml.safe_load(state['profile'])
        nodes = {source: [copy.deepcopy(node) for node in profile['proxies'] if node.get('name') == name]
                 for source, name in NAMES.items()}
    except (KeyError, TypeError, ValueError, yaml.YAMLError):
        raise RuntimeError('An integrated current profile cannot be parsed') from None
    require(all(len(items) == 1 for items in nodes.values()), 'An integrated profile lacks a unique transport node')
    nodes = {source: items[0] for source, items in nodes.items()}
    entry = integration['accounts'].get(identity, {})
    require(entry.get('port') == port, 'The HY2 registry targets another account port')
    for node in nodes.values():
        require(node.get('server') == live.IP and node.get('port') == port,
                'A transport node targets an unexpected public entrance')
        require(not node.get('dialer-proxy'), 'A current transport node has an unexpected dialer')
    hy2, tcp = nodes['hy2'], nodes['xray']
    require(hy2.get('type') == 'hysteria2' and hy2.get('password') == entry.get('password') and hy2.get('udp') is False
            and hy2.get('skip-cert-verify') is False
            and hy2.get('fingerprint', '').replace(':', '').lower() == integration['certificate_sha256']
            and hy2.get('sni') == integration['sni'], 'The HY2 profile identity or certificate pin is inconsistent')
    require(tcp.get('type') == 'vless' and tcp.get('uuid') == state.get('auto_id'),
            'The REALITY compatibility identity differs from the account AUTO identity')
    uuid.UUID(tcp['uuid'])
    groups = [group for group in profile.get('proxy-groups', []) if group.get('name') == 'AUTO · 网页切换']
    require(len(groups) == 1 and groups[0].get('type') == 'fallback'
            and groups[0].get('proxies') == [NAMES['hy2'], NAMES['xray']], 'AUTO does not prioritize HY2 then REALITY')
    return nodes


def collect_accounts(sftp):
    registry = private_json(sftp, OWNER + '/users.private.json')
    integration = private_json(sftp, OWNER + '/hy2.private.json')
    health = private_json(sftp, OWNER + '/health.private.json')
    store = ledger(sftp)
    require(integration.get('enabled') is True, 'The HY2 integration is not enabled yet')
    records = [{'id': 'admin', 'port': 443, 'enabled': True}] + registry['users']
    require(len(records) == 3 and {record.get('port') for record in records} == {443, 1443, 2443},
            'Three distinct account entrances are required for this acceptance')
    accounts = []
    for record in sorted(records, key=lambda item: item['port']):
        identity = record['id']
        require(identity == 'admin' or re.fullmatch(r'[a-f0-9]{16}', identity), 'Unexpected account identity')
        require(record.get('enabled') is True, 'Acceptance will not enable a disabled account')
        state_path = OWNER + ('/state.private.json' if identity == 'admin' else '/users/' + identity + '/state.private.json')
        state = private_json(sftp, state_path)
        user = store.get('users', {}).get(identity, {})
        used = sum(month_totals(store, identity, datetime.now(timezone.utc).strftime('%Y-%m')).values())
        quota = user.get('quota_bytes', 0)
        require(not quota or used < quota, 'Acceptance will not bypass an exhausted quota')
        nodes = validate_nodes(state, integration, identity, record['port'])
        accounts.append({'id': identity, 'port': record['port'], 'record': record, 'state_path': state_path,
                         'nodes': nodes, 'expected_ip': expected_ip(state, health.get(identity, {})),
                         'settings_hash': settings_hash(state, record, store),
                         'profile_sha256': hashlib.sha256(state['profile'].encode('utf-8')).hexdigest()})
    return accounts, store


# Private secrets and source labels are read only on the VPS. Output contains
# numeric aggregates and a public process epoch, never private response bodies.
NATIVE_PROGRAM = r'''
import hashlib, json, re, subprocess, sys
from pathlib import Path
from urllib.request import Request, ProxyHandler, build_opener
identity, port, source = sys.argv[1], int(sys.argv[2]), sys.argv[3]
assert identity == 'admin' or re.fullmatch(r'[a-f0-9]{16}', identity)
assert port in (443, 1443, 2443) and source in ('hy2', 'xray')
service = ('raksmart-hy2@' + str(port) + '.service' if source == 'hy2' else
           'xray.service' if identity == 'admin' else 'xray-panel@' + identity + '.service')
epoch = subprocess.check_output(['systemctl', 'show', service, '--property=MainPID',
                                 '--property=ExecMainStartTimestampMonotonic'], timeout=5)
if source == 'hy2':
    registry = json.loads(Path('/var/lib/vps-panel/hy2.private.json').read_text())
    entry = registry['accounts'][identity]
    assert registry['enabled'] and entry['port'] == port
    query = Request('http://127.0.0.1:' + str(18600 + port) + '/traffic',
                    headers={'Authorization': entry['api_secret']})
    with build_opener(ProxyHandler({})).open(query, timeout=3) as response:
        data = json.loads(response.read().decode('utf-8'))
    assert isinstance(data, dict) and not set(data) - {'user'}
    values = data.get('user', {'tx': 0, 'rx': 0})
    totals = {'up_bytes': values['tx'], 'down_bytes': values['rx']}
else:
    output = subprocess.check_output(['/usr/local/bin/xray', 'api', 'statsquery',
        '--server=127.0.0.1:' + str(15000 + port), '-timeout', '3', '-pattern', 'user>>>'], timeout=6)
    text = output.decode('utf-8', 'replace')
    data = json.loads(text[text.index('{'):])
    totals = {'up_bytes': 0, 'down_bytes': 0}
    for item in data.get('stat', []):
        name = item.get('name', '')
        if re.fullmatch(r'user>>>[^\r\n]+>>>traffic>>>(uplink|downlink)', name):
            totals['up_bytes' if name.endswith('>>>uplink') else 'down_bytes'] += int(item.get('value', 0))
assert all(type(value) is int and value >= 0 for value in totals.values())
totals['epoch_sha256'] = hashlib.sha256(epoch).hexdigest()
print(json.dumps(totals))
'''


def native_snapshot(client, account, source):
    command = ('python3 -c ' + shlex.quote(NATIVE_PROGRAM) + ' ' + shlex.quote(account['id'])
               + ' ' + str(account['port']) + ' ' + source)
    code, output, _ = execute(client, command, timeout=15)
    require(code == 0, 'A read-only native transport counter is unavailable')
    result = json.loads(output)
    require(set(result) == {'up_bytes', 'down_bytes', 'epoch_sha256'}, 'Unexpected native transport output')
    return result


def counter_delta(before, after):
    require(before['epoch_sha256'] == after['epoch_sha256'], 'A transport process restarted during acceptance')
    delta = {key: after[key] - before[key] for key in ('up_bytes', 'down_bytes')}
    require(all(value >= 0 for value in delta.values()), 'A native transport counter reset during acceptance')
    return delta


def configuration(nodes, proxy_port, controller_port, secret):
    return {'mixed-port': proxy_port, 'port': 0, 'socks-port': 0, 'allow-lan': False,
            'bind-address': '127.0.0.1', 'ipv6': False, 'tun': {'enable': False},
            'interface-name': 'WLAN', 'dns': {'enable': False}, 'log-level': 'warning',
            'mode': 'rule', 'external-controller': '127.0.0.1:' + str(controller_port), 'secret': secret,
            'profile': {'store-selected': False, 'store-fake-ip': False}, 'proxies': copy.deepcopy(nodes),
            'proxy-groups': [{'name': 'VERIFY', 'type': 'select', 'proxies': [node['name'] for node in nodes]}],
            'rules': ['MATCH,VERIFY']}


class IsolatedClient:
    def __init__(self, directory, nodes):
        self.directory = directory
        self.proxy_port, self.control_port = free_port(), free_port()
        while self.proxy_port == self.control_port:
            self.control_port = free_port()
        self.secret = secrets.token_urlsafe(32)
        self.process = None
        self.log = None
        self.opener = build_opener(ProxyHandler({}))
        self.candidate = directory / 'acceptance.private.yaml'
        self.candidate.write_text(yaml.safe_dump(configuration(nodes, self.proxy_port, self.control_port, self.secret),
                                                  allow_unicode=True, sort_keys=False), encoding='utf-8')

    def syntax(self):
        self.log = (self.directory / 'client.private.log').open('w', encoding='utf-8')
        result = subprocess.run([str(BINARY), '-t', '-d', str(self.directory), '-f', str(self.candidate)],
                                stdout=self.log, stderr=subprocess.STDOUT, timeout=30, creationflags=live.NO_WINDOW)
        require(result.returncode == 0, 'Official Mihomo rejected the isolated current transport nodes')

    def start(self):
        self.syntax()
        self.process = subprocess.Popen([str(BINARY), '-d', str(self.directory), '-f', str(self.candidate)],
                                        stdout=self.log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                        creationflags=live.NO_WINDOW)
        deadline = time.monotonic() + 20
        while True:
            require(self.process.poll() is None, 'The isolated client exited')
            try:
                self.api('/version')
                return
            except OSError:
                require(time.monotonic() < deadline, 'The isolated client controller did not start')
                time.sleep(.2)

    def api(self, path, method='GET', data=None):
        query = Request('http://127.0.0.1:' + str(self.control_port) + path,
                        json.dumps(data).encode('utf-8') if data is not None else None,
                        {'Authorization': 'Bearer ' + self.secret, 'Content-Type': 'application/json'}, method=method)
        with self.opener.open(query, timeout=5) as response:
            payload = response.read()
            return json.loads(payload) if payload else None

    def select(self, name):
        self.api('/connections', 'DELETE')
        self.api('/proxies/' + quote('VERIFY', safe=''), 'PUT', {'name': name})

    def curl(self, arguments, payload=None, timeout=15):
        result = subprocess.run([CURL, '--proxy', 'socks5h://127.0.0.1:' + str(self.proxy_port),
                                 '--noproxy', '', '--connect-timeout', '5', '--max-time', str(timeout),
                                 '--ssl-no-revoke', '--silent', '--show-error'] + arguments,
                                input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout + 4, creationflags=live.NO_WINDOW)
        return result

    def identity(self, name, positive=True):
        self.select(name)
        for attempt in range(3 if positive else 1):
            result = self.curl(['https://api.ipify.org'], timeout=12 if positive else 8)
            if result.returncode == 0 or not positive:
                break
            time.sleep(.2)
        observed = None
        if result.returncode == 0:
            try:
                observed = str(ipaddress.ip_address(result.stdout.decode('ascii').strip()))
            except (ValueError, UnicodeError):
                raise RuntimeError('The external IP service returned an invalid response') from None
        return {'curl_exit_code': result.returncode, 'observed_ip': observed}

    def transfer(self, name, direction, size, timeout=25):
        self.select(name)
        formatting = '{"http_code":%{http_code},"size_download":%{size_download},"size_upload":%{size_upload},"time_total":%{time_total},"time_starttransfer":%{time_starttransfer}}'
        arguments = ['--output', 'NUL', '--write-out', formatting]
        payload = None
        if direction == 'upload':
            payload = bytes(size)
            arguments += ['--request', 'POST', '--header', 'Content-Type: application/octet-stream',
                          '--header', 'Expect:', '--data-binary', '@-', 'https://speed.cloudflare.com/__up']
        else:
            arguments += ['https://speed.cloudflare.com/__down?bytes=' + str(size)]
        started = time.perf_counter()
        result = self.curl(arguments, payload, timeout)
        elapsed = time.perf_counter() - started
        try:
            data = json.loads(result.stdout.decode('ascii'))
        except (ValueError, UnicodeError):
            data = {}
        actual = data.get('size_upload' if direction == 'upload' else 'size_download', 0)
        return {'direction': direction, 'requested_bytes': size, 'actual_bytes': actual,
                'curl_exit_code': result.returncode, 'http_code': data.get('http_code'),
                'first_byte_ms': round(data['time_starttransfer'] * 1000, 2) if isinstance(data.get('time_starttransfer'), (int, float)) else None,
                'curl_total_seconds': data.get('time_total'),
                'wall_seconds': round(elapsed, 4), 'mbps_including_startup': round(actual * 8 / elapsed / 1e6, 3),
                'success': result.returncode == 0 and data.get('http_code') == 200 and actual == size}

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.log is not None:
            self.log.close()


def synthetic_nodes():
    public = base64.urlsafe_b64encode(bytes(range(1, 33))).decode('ascii').rstrip('=')
    return [{'name': NAMES['hy2'], 'type': 'hysteria2', 'server': live.IP, 'port': 443,
             'password': 'synthetic-only-password', 'sni': 'raksmart-hy2.local', 'skip-cert-verify': False,
             'fingerprint': '01' * 32, 'udp': False, 'bbr-profile': 'standard'},
            {'name': NAMES['xray'], 'type': 'vless', 'server': live.IP, 'port': 443,
             'uuid': str(uuid.uuid4()), 'tls': True, 'udp': False, 'servername': 'www.microsoft.com',
             'client-fingerprint': 'chrome', 'flow': 'xtls-rprx-vision',
             'reality-opts': {'public-key': public, 'short-id': '0123456789abcdef'}}]


def check_native_parser():
    ast.parse(NATIVE_PROGRAM, feature_version=(3, 6))
    # Exercise the exact remote program with synthetic subprocess results.
    # No SSH, private file, URL, or process start is involved.
    fixture = {'stat': [
        {'name': 'user>>>panel-auto@exits.invalid>>>traffic>>>uplink', 'value': 123},
        {'name': 'user>>>panel-auto@exits.invalid>>>traffic>>>downlink', 'value': 456},
        {'name': 'user>>>fixed@exits.invalid>>>traffic>>>uplink', 'value': 7},
        {'name': 'outbound>>>direct>>>traffic>>>uplink', 'value': 99999}]}

    def response(arguments, **kwargs):
        if arguments[0] == 'systemctl':
            return b'MainPID=7\nExecMainStartTimestampMonotonic=1234\n'
        require(arguments[0] == '/usr/local/bin/xray' and '-reset' not in arguments,
                'Native counter fixture unexpectedly resets counters')
        return json.dumps(fixture).encode('utf-8')

    stream = io.StringIO()
    with patch('sys.argv', ['native', 'admin', '443', 'xray']), patch('subprocess.check_output', response), contextlib.redirect_stdout(stream):
        exec(compile(NATIVE_PROGRAM, '<native-statistics>', 'exec'), {})
    parsed = json.loads(stream.getvalue())
    require(parsed['up_bytes'] == 130 and parsed['down_bytes'] == 456,
            'Native counter aggregation failed the synthetic evidence check')
    require(len(parsed['epoch_sha256']) == 64, 'Native epoch evidence is invalid')


def check_profile_contract():
    nodes = synthetic_nodes()
    nodes[1].pop('udp')  # Existing REALITY renderers omit the optional UDP key.
    state = {'auto_id': nodes[1]['uuid'], 'profile': yaml.safe_dump({'proxies': nodes,
        'proxy-groups': [{'name': 'AUTO · 网页切换', 'type': 'fallback', 'proxies': list(NAMES.values())}]}, allow_unicode=True)}
    registry = {'accounts': {'admin': {'port': 443, 'password': nodes[0]['password']}},
                'certificate_sha256': nodes[0]['fingerprint'], 'sni': nodes[0]['sni']}
    require(set(validate_nodes(state, registry, 'admin', 443)) == {'hy2', 'xray'},
            'Current transport profile contract failed its synthetic check')


def run(check_local=False, rounds=1, size=1048576):
    report = {'success': False, 'checked_at': datetime.now(timezone.utc).isoformat(),
              'server': live.IP, 'physical_wlan': True, 'tun_disabled': True,
              'configuration_changes': 0, 'credential_changes': 0, 'exit_changes': 0,
              'samples': [], 'isolation': [], 'comparison': []}
    phase = 'local-core'
    directory = TEMP_ROOT / secrets.token_hex(8)
    isolated = None
    ssh = None
    sftp = None
    try:
        require(BINARY.is_file() and not BINARY.is_symlink(), 'Official Mihomo is unavailable')
        require(not TEMP_ROOT.is_symlink(), 'Unsafe isolated client parent')
        directory.mkdir(parents=True, exist_ok=False)
        report['core_sha256'] = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        if check_local:
            isolated = IsolatedClient(directory, synthetic_nodes())
            isolated.syntax()
            check_native_parser()
            check_profile_contract()
            report.update(success=True, local_syntax_only=True, native_synthetic_fixture_verified=True,
                          profile_contract_verified=True, remote_python_syntax='3.6', server_requests=0)
            return report
        phase = 'private-current-profile-reads'
        ssh = connect()
        sftp = ssh.open_sftp()
        accounts, before_store = collect_accounts(sftp)
        month = datetime.now(timezone.utc).strftime('%Y-%m')
        before_month = {account['id']: month_totals(before_store, account['id'], month) for account in accounts}
        before_sources = {account['id']: {source: source_totals(before_store, account['id'], source)
                                         for source in NAMES} for account in accounts}
        nodes = []
        for account in accounts:
            for source, node in account['nodes'].items():
                node['name'] = source + '-' + str(account['port'])
                node['udp'] = False
                nodes.append(node)
        for account in accounts[1:]:
            other = next(item for item in accounts[1:] if item is not account)
            wrong = copy.deepcopy(account['nodes']['hy2'])
            require(wrong['password'] != other['nodes']['hy2']['password'], 'HY2 credentials are shared across accounts')
            wrong.update(name='wrong-hy2-' + str(account['port']), password=other['nodes']['hy2']['password'])
            nodes.append(wrong)
        phase = 'isolated-client'
        isolated = IsolatedClient(directory, nodes)
        isolated.start()
        report['official_current_nodes_accepted'] = True
        phase = 'both-public-transports-and-native-counters'
        for account in accounts:
            for source in ('hy2', 'xray'):
                before = native_snapshot(ssh, account, source)
                outcome = isolated.identity(account['nodes'][source]['name'])
                after = native_snapshot(ssh, account, source)
                delta = counter_delta(before, after)
                sample = {'port': account['port'], 'account': account['id'], 'protocol': source,
                          'profile_sha256': account['profile_sha256'], 'expected_ip': account['expected_ip'],
                          'native_counter_delta': delta, 'native_counter_incremented': all(value > 0 for value in delta.values())}
                sample.update(outcome)
                sample['public_exit_verified'] = outcome['curl_exit_code'] == 0 and outcome['observed_ip'] == account['expected_ip']
                report['samples'].append(sample)
                require(sample['public_exit_verified'], 'A forced public transport did not use the current web-selected exit')
                require(sample['native_counter_incremented'], 'A forced transport did not increment its own native counters')
        phase = 'other-account-hy2-password-rejection'
        for account in accounts[1:]:
            bad = isolated.identity('wrong-hy2-' + str(account['port']), positive=False)
            good = isolated.identity(account['nodes']['hy2']['name'])
            result = {'port': account['port'], 'wrong_password_curl_exit_code': bad['curl_exit_code'],
                      'other_account_password_rejected': bad['curl_exit_code'] != 0 and bad['observed_ip'] is None,
                      'valid_password_after_negative': good['observed_ip'] == account['expected_ip'] and good['curl_exit_code'] == 0}
            report['isolation'].append(result)
            require(result['other_account_password_rejected'] and result['valid_password_after_negative'],
                    'Cross-account HY2 credential isolation failed')
        phase = 'bounded-equal-payload-comparison'
        admin = accounts[0]
        report['comparison_method'] = {'account_port': admin['port'], 'rounds': rounds, 'bytes_per_transfer': size,
            'streams': 1, 'same_payload_and_urls': True, 'alternating_protocol_order': True,
            'throughput_includes_handshake_and_http': True, 'only_current_selected_exit_used': True}
        for round_index in range(rounds):
            order = ('hy2', 'xray') if round_index % 2 == 0 else ('xray', 'hy2')
            for direction in ('download', 'upload'):
                for source in order:
                    result = isolated.transfer(admin['nodes'][source]['name'], direction, size)
                    result.update(round=round_index + 1, protocol=source)
                    report['comparison'].append(result)
        # Comparison failures remain visible but do not erase verified transport,
        # egress and account-isolation evidence from the acceptance report.
        report['comparison_completed'] = all(item['success'] for item in report['comparison'])
        phase = 'combined-monthly-accounting'
        isolated.api('/connections', 'DELETE')
        deadline = time.monotonic() + 35
        while True:
            require(datetime.now(timezone.utc).strftime('%Y-%m') == month, 'Acceptance crossed a UTC billing month')
            after_store = ledger(sftp)
            deltas = {account['id']: {key: month_totals(after_store, account['id'], month)[key] - before_month[account['id']][key]
                                     for key in ('up_bytes', 'down_bytes')} for account in accounts}
            source_deltas = {account['id']: {source: source_delta(before_sources[account['id']][source],
                                  source_totals(after_store, account['id'], source)) for source in NAMES} for account in accounts}
            minimums = {account['id']: {key: sum(sample['native_counter_delta'][key] for sample in report['samples']
                                                if sample['account'] == account['id'])
                                      for key in ('up_bytes', 'down_bytes')} for account in accounts}
            sampled = all(all(value >= minimums[identity][key] for key, value in delta.items())
                          and all(all(amount > 0 for amount in item.values()) for item in source_deltas[identity].values())
                          for identity, delta in deltas.items())
            if sampled or time.monotonic() >= deadline:
                break
            time.sleep(2)
        report['monthly_traffic_deltas'] = [{'account': identity, 'month': month, **delta} for identity, delta in deltas.items()]
        report['persisted_source_counter_deltas'] = [{'account': identity, 'protocol': source, **delta}
            for identity, sources in source_deltas.items() for source, delta in sources.items()]
        report['combined_monthly_traffic_recorded'] = sampled
        phase = 'settings-preservation'
        current_registry = private_json(sftp, OWNER + '/users.private.json')
        current_records = {'admin': accounts[0]['record']}
        current_records.update({record['id']: record for record in current_registry['users']})
        report['settings_preserved'] = all(
            settings_hash(private_json(sftp, account['state_path']), current_records.get(account['id']), after_store)
            == account['settings_hash'] for account in accounts)
        report.update(success=report['settings_preserved'] and sampled, completed=True,
                      forced_public_protocol_count=len(report['samples']), ssh_proxy_fallback_used=False)
        return report
    except Exception as error:
        # Do not print exception messages: they can contain credentials or URLs.
        report.update(failed=True, failure_phase=phase, error_type=type(error).__name__)
        return report
    finally:
        if isolated is not None:
            isolated.close()
        if sftp is not None:
            sftp.close()
        if ssh is not None:
            ssh.close()
        require(directory.resolve().parent == TEMP_ROOT.resolve() and not directory.is_symlink()
                and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe isolated client cleanup path')
        if directory.exists():
            shutil.rmtree(str(directory))
        report['temporary_private_files_removed'] = not directory.exists()
        report['own_client_process_terminated'] = isolated is None or isolated.process is None or isolated.process.poll() is not None
        if not check_local:
            REPORT.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check-local', action='store_true')
    mode.add_argument('--run', action='store_true')
    parser.add_argument('--rounds', type=int, choices=(1, 2), default=1)
    parser.add_argument('--bytes', type=int, default=1048576)
    args = parser.parse_args()
    if not 262144 <= args.bytes <= 4194304:
        parser.error('--bytes must be between 256 KiB and 4 MiB')
    result = run(args.check_local, args.rounds, args.bytes)
    print(json.dumps(result))
    sys.exit(0 if result.get('success') else 1)
