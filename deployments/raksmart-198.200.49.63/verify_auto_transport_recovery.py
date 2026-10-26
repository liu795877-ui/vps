"""Isolated actual AUTO fallback and recovery acceptance, without bulk load.

--check-local is offline. --run reads the current production admin profile,
uses its actual HY2/REALITY nodes and AUTO group in a minimal MATCH,AUTO client,
then breaks only this child's HY2 destination port and restores it with a local
controller reload. The current user's proxy and production config never change.
No subscription/rule-provider URLs or credentials are written to public output.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time
import traceback
from urllib.parse import quote

import yaml

import benchmark_hy2_latency as base
import verify_hy2_clients as helpers


AUTO = 'AUTO · 网页切换'
HY2 = helpers.NAMES['hy2']
REALITY = helpers.NAMES['xray']
HEALTH = {'url': 'https://www.gstatic.com/generate_204', 'expected-status': '204',
          'interval': 30, 'lazy': False, 'timeout': 5000}
UNAVAILABLE_PORT = 65534


class AutoClient(base.BenchClient):
    def __init__(self, directory, nodes, group, clock_start):
        directory.mkdir()
        helpers.IsolatedClient.__init__(self, directory, nodes)
        self.clock_start = clock_start
        self.children, self.all_children = set(), set()
        self.children_lock = threading.Lock()
        self.config = helpers.configuration(nodes, self.proxy_port, self.control_port, self.secret)
        self.config['proxy-groups'] = [copy.deepcopy(group)]
        self.config['rules'] = ['MATCH,' + AUTO]
        self.write_config()

    def write_config(self):
        self.candidate.write_text(yaml.safe_dump(self.config, allow_unicode=True, sort_keys=False), encoding='utf-8')

    def restore_hy2(self, port):
        self.config['proxies'][0]['port'] = port
        self.write_config()
        self.api('/configs?force=true', 'PUT', {'path': str(self.candidate)})

    def safe_group_state(self):
        result = self.api('/proxies/' + quote(AUTO, safe=''))
        nodes = {}
        for name in (HY2, REALITY):
            item = self.api('/proxies/' + quote(name, safe=''))
            nodes[name] = {'alive': item.get('alive'),
                'history': [{'delay': row.get('delay'), 'time': row.get('time')}
                            for row in (item.get('history') or [])[-3:] if isinstance(row, dict)]}
        return {'selected': result.get('now'), 'nodes': nodes}


def actual_group(profile, use_production_policy):
    groups = [copy.deepcopy(group) for group in profile.get('proxy-groups', []) if group.get('name') == AUTO]
    helpers.require(len(groups) == 1 and groups[0].get('type') == 'fallback'
                    and groups[0].get('proxies') == [HY2, REALITY], 'Actual AUTO group is not HY2-first fallback')
    group = groups[0]
    if use_production_policy:
        helpers.require(all(group.get(key) == value for key, value in HEALTH.items()),
                        'Production AUTO health policy differs from the accepted candidate')
    else:
        group.update(HEALTH)
    return group


def wait_selection(client, expected, stage):
    deadline = time.monotonic() + 42
    observations = []
    while True:
        item = client.safe_group_state()
        item['at'] = base.utc()
        observations.append(item)
        selected_node = item['nodes'][expected]
        latest_delay = selected_node['history'][-1].get('delay') if selected_node['history'] else None
        if (item['selected'] == expected and isinstance(latest_delay, (int, float)) and latest_delay > 0):
            return {'selected': expected, 'observations': observations, 'automatic_healthcheck_used': True}
        helpers.require(time.monotonic() < deadline, 'Automatic fallback/recovery selection timed out')
        base.emit('selection-wait', stage, selected=item['selected'], expected=expected)
        time.sleep(2)


def light_with_chain(client, account):
    chain_records = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        job = pool.submit(client.request, 'light', account['expected_ip'], 0, 10)
        while not job.done():
            state = client.api('/connections')
            for item in (state.get('connections') or []):
                if not isinstance(item, dict):
                    continue
                metadata = item.get('metadata') or {}
                if metadata.get('host') == 'api.ipify.org':
                    chains = [name for name in (item.get('chains') or []) if name in (AUTO, HY2, REALITY)]
                    if chains and chains not in chain_records:
                        chain_records.append(chains)
            time.sleep(.05)
        result = job.result()
    result['observed_business_connection_chains'] = chain_records
    return result


def gstatic(client):
    arguments = [helpers.CURL, '--proxy', 'socks5h://127.0.0.1:' + str(client.proxy_port), '--noproxy', '',
        '--connect-timeout', '5', '--max-time', '10', '--ssl-no-revoke', '--silent', '--show-error',
        '--output', 'NUL', '--write-out', '{"http_code":%{http_code},"time_starttransfer":%{time_starttransfer}}',
        HEALTH['url']]
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=13, creationflags=base.live.NO_WINDOW)
    try:
        metrics = json.loads(result.stdout)
    except ValueError:
        metrics = {}
    return {'success': result.returncode == 0 and metrics.get('http_code') == 204,
            'http_code': metrics.get('http_code'), 'curl_exit_code': result.returncode,
            'ttfb_ms': round(metrics['time_starttransfer'] * 1000, 3)
                       if isinstance(metrics.get('time_starttransfer'), (int, float)) else None}


def verify_stage(client, ssh, account, expected, label):
    base.emit('phase-start', label)
    selection = wait_selection(client, expected, label)
    before = {kind: helpers.native_snapshot(ssh, account, kind) for kind in ('hy2', 'xray')}
    identity = light_with_chain(client, account)
    health = gstatic(client)
    after = {kind: helpers.native_snapshot(ssh, account, kind) for kind in ('hy2', 'xray')}
    delta = {kind: helpers.counter_delta(before[kind], after[kind]) for kind in before}
    expected_source = 'hy2' if expected == HY2 else 'xray'
    chain_ok = any(expected in chains and AUTO in chains for chains in identity['observed_business_connection_chains'])
    result = {'selection': selection, 'business_identity': identity, 'health_url_request': health,
              'native_account_counter_delta': delta,
              'native_counter_scope': 'all admin traffic during requests, not isolated-client-only',
              'expected_business_transport_chain_observed': chain_ok,
              'success': identity['success'] and health['success'] and chain_ok
                         and sum(delta[expected_source].values()) > 0}
    base.emit('phase-end', label, success=result['success'], expected=expected, chain_observed=chain_ok)
    return result


def run(args):
    directory = base.TEMP_ROOT / secrets.token_hex(8)
    client, ssh, sftp = None, None, None
    started = time.monotonic()
    report = {'success': False, 'started_at': base.utc(), 'mode': 'run' if args.run else 'local-check',
              'configuration_changes': 0, 'credential_changes': 0, 'exit_changes': 0,
              'isolated_hy2_port_changes': 2, 'candidate_health_policy': HEALTH,
              'production_policy_required': args.production_policy, 'cleanup_errors': []}
    stage = 'local-gate'
    try:
        helpers.require(not base.TEMP_ROOT.is_symlink(), 'Unsafe private parent')
        report['private_directory_acl'] = base.make_private(directory)
        report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['core_sha256'] = hashlib.sha256(helpers.BINARY.read_bytes()).hexdigest()
        report['method'] = {'group_from_current_full_admin_profile': True,
            'nodes_from_current_full_admin_profile': True,
            'rule_scope': 'minimal MATCH,AUTO to isolate transport; production DNS/providers/rules unchanged',
            'tun': False, 'physical_interface': 'WLAN', 'bind_address': '127.0.0.1',
            'only_isolated_hy2_port_broken': UNAVAILABLE_PORT, 'recovery': 'same-process local controller reload',
            'automatic_health_check_selection': True, 'bulk_download_bytes': 0}
        if args.check_local:
            nodes = helpers.synthetic_nodes()
            group = actual_group({'proxy-groups': [{'name': AUTO, 'type': 'fallback',
                                  'proxies': [HY2, REALITY]}]}, False)
            client = AutoClient(directory / 'synthetic', nodes, group, started)
            client.syntax()
            helpers.require(client.config['rules'] == ['MATCH,' + AUTO], 'AUTO isolation contract failed')
            helpers.require(actual_group({'proxy-groups': [group]}, True) == group, 'Production health contract failed')
            report.update(success=True, offline_check=True, server_requests=0)
            return report
        stage = 'current-private-reads'
        ssh = helpers.connect()
        sftp = ssh.open_sftp()
        sftp.get_channel().settimeout(20)
        accounts, before_store = helpers.collect_accounts(sftp)
        account = next(item for item in accounts if item['id'] == 'admin')
        state = helpers.private_json(sftp, account['state_path'])
        helpers.require(state.get('active_id') in (None, 'server') and account['expected_ip'] == base.live.IP,
                        'Current AUTO server exit is required; verifier will not switch it')
        full_profile = yaml.safe_load(state['profile'])
        group = actual_group(full_profile, args.production_policy)
        report['actual_group_health_policy'] = {key: group.get(key) for key in HEALTH}
        report['profile_sha256'] = account['profile_sha256']
        report['account_settings_sha256'] = account['settings_hash']
        # Sanitize a remote socket check: only a boolean leaves the server.
        check_program = "import json,subprocess,re; t=subprocess.check_output(['ss','-H','-lun']).decode(); print(json.dumps({'unavailable_port_unused': not any(re.search(r':65534\\s',x) for x in t.splitlines())}))"
        import shlex
        code, output, _ = helpers.execute(ssh, 'python3 -c ' + shlex.quote(check_program), timeout=10)
        helpers.require(code == 0 and json.loads(output).get('unavailable_port_unused') is True,
                        'Isolated failure port is not confirmed unused')
        nodes = [copy.deepcopy(account['nodes'][source]) for source in ('hy2', 'xray')]
        true_port = nodes[0]['port']
        nodes[0]['port'] = UNAVAILABLE_PORT
        stage = 'isolated-start'
        client = AutoClient(directory / 'actual-auto', nodes, group, started)
        client.start(time.monotonic() + 35)
        stage = 'automatic-tcp-fallback'
        report['automatic_tcp_fallback'] = verify_stage(client, ssh, account, REALITY, stage)
        helpers.require(report['automatic_tcp_fallback']['success'], 'Business traffic did not verify TCP fallback')
        stage = 'isolated-hy2-recovery-reload'
        old_pid = client.process.pid
        client.restore_hy2(true_port)
        report['same_isolated_process_after_reload'] = client.process.poll() is None and client.process.pid == old_pid
        stage = 'automatic-hy2-recovery'
        report['automatic_hy2_recovery'] = verify_stage(client, ssh, account, HY2, stage)
        stage = 'settings-preservation'
        after_store = helpers.ledger(sftp)
        registry = helpers.private_json(sftp, helpers.OWNER + '/users.private.json')
        records = {'admin': account['record'], **{item['id']: item for item in registry['users']}}
        report['all_settings_preserved'] = all(helpers.settings_hash(
            helpers.private_json(sftp, item['state_path']), records.get(item['id']), after_store) == item['settings_hash']
            for item in accounts)
        month = datetime.now(timezone.utc).strftime('%Y-%m')
        report['normal_monthly_ledger_delta'] = {key: helpers.month_totals(after_store, 'admin', month)[key]
            - helpers.month_totals(before_store, 'admin', month)[key] for key in ('up_bytes', 'down_bytes')}
        report['success'] = (report['automatic_hy2_recovery']['success'] and report['same_isolated_process_after_reload']
                             and report['all_settings_preserved'])
        return report
    except Exception as error:
        report.update(failure_stage=stage, error_type=type(error).__name__)
        frame = traceback.extract_tb(error.__traceback__)[-1]
        report['safe_error_location'] = {'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
        return report
    finally:
        if client is not None:
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
                            and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe cleanup path')
            if directory.exists():
                shutil.rmtree(str(directory))
        except Exception as error:
            report['cleanup_errors'].append('directory:' + type(error).__name__)
        report['own_mihomo_process_terminated'] = client is None or client.process is None or client.process.poll() is not None
        report['own_curl_processes_terminated'] = client is None or all(p.poll() is not None for p in client.all_children)
        report['temporary_private_files_removed'] = not directory.exists()
        report['finished_at'] = base.utc()
        report['total_wall_seconds'] = round(time.monotonic() - started, 3)
        if report['cleanup_errors'] or not all(report[key] for key in ('own_mihomo_process_terminated',
                'own_curl_processes_terminated', 'temporary_private_files_removed')):
            report['success'] = False
        if args.run:
            (helpers.FOLDER / ('auto-transport-' + args.label + '.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run', action='store_true')
    group.add_argument('--check-local', action='store_true')
    parser.add_argument('--production-policy', action='store_true')
    parser.add_argument('--label', default='candidate', type=lambda value: value if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', value)
                        else parser.error('Simple lowercase ASCII label required'))
    result = run(parser.parse_args())
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result.get('success') else 1)
