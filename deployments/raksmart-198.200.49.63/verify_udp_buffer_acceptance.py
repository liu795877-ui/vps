"""Six bounded exit checks after UDP buffer maintenance; no speed/load tests.

Only --run connects. Reuses the physical-WLAN SSH and isolated Mihomo helpers.
Credentials stay in memory or a verified private temporary directory. Live
sources are checked through their native APIs and fresh normal ledger samples;
this does not create web sessions or change passwords, exits or configurations.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import shlex
import time

import benchmark_hy2_latency as benchmark
import verify_hy2_clients as helpers


REPORT = helpers.FOLDER / 'udp-buffer-acceptance.json'
NATIVE_PROGRAM = helpers.NATIVE_PROGRAM.replace(
    "totals['epoch_sha256'] = hashlib.sha256(epoch).hexdigest()",
    "after_epoch = subprocess.check_output(['systemctl', 'show', service, '--property=MainPID', '--property=ExecMainStartTimestampMonotonic'], timeout=5)\n"
    "assert epoch == after_epoch\n"
    "fields = dict(line.split('=', 1) for line in epoch.decode('utf-8').strip().splitlines() if '=' in line)\n"
    "assert int(fields['MainPID']) > 0\n"
    "canonical = '\\n'.join(key + '=' + fields[key] for key in ('MainPID', 'ExecMainStartTimestampMonotonic'))\n"
    "totals['epoch_sha256'] = hashlib.sha256(canonical.encode('utf-8')).hexdigest()")


def native_snapshot(ssh, account, source):
    command = 'python3 -c ' + shlex.quote(NATIVE_PROGRAM) + ' ' + shlex.quote(account['id']) + ' ' + str(account['port']) + ' ' + source
    code, output, unused_error = helpers.execute(ssh, command, timeout=15)
    helpers.require(code == 0, 'Native source is unavailable or changed process epoch')
    return json.loads(output)


def protected(sftp, accounts):
    paths = [helpers.OWNER + '/' + name for name in ('auth.private.json',
        'users.private.json', 'hy2.private.json', 'hy2-server.crt.pem', 'hy2-server.key.pem')]
    paths += [account['state_path'] for account in accounts]
    paths += ['/usr/local/etc/raksmart-hy2/accounts/' + str(account['port']) + '.yaml'
              for account in accounts]
    paths += ['/usr/local/etc/xray/config.json' if account['id'] == 'admin' else
        '/usr/local/etc/xray-members/' + account['id'] + '/config.json' for account in accounts]
    result = {}
    for path in paths:
        with sftp.open(path, 'rb') as stream:
            result[path] = hashlib.sha256(stream.read()).hexdigest()
    return result


def ledger_checks(before, after, accounts, month, native_after, completed_at, minimums):
    checks = []
    for account in accounts:
        identity = account['id']
        old_user, new_user = before['users'][identity], after['users'][identity]
        helpers.require(all(old_user[key] == new_user[key] for key in ('quota_bytes', 'rate_bps')),
                        'Traffic limits changed during acceptance')
        for old_month, totals in old_user['months'].items():
            helpers.require(all(new_user['months'].get(old_month, {}).get(key, -1) >= amount
                                for key, amount in totals.items()), 'Monthly totals moved backwards')
        totals = helpers.month_totals(after, identity, month)
        previous = helpers.month_totals(before, identity, month)
        recorded = all(totals[key] - previous[key] >= minimums[identity][key] for key in totals)
        for source in ('hy2', 'xray'):
            data = new_user.get('sources', {}).get(source, {})
            stored = helpers.source_totals(after, identity, source)
            native = native_after[(identity, source)]
            saved_epoch = data.get('epoch')
            fields = dict(line.split('=', 1) for line in (saved_epoch or '').splitlines() if '=' in line)
            canonical = '\n'.join(key + '=' + fields.get(key, '') for key in ('MainPID', 'ExecMainStartTimestampMonotonic'))
            epoch_matches = isinstance(saved_epoch, str) and hashlib.sha256(
                canonical.encode('utf-8')).hexdigest() == native['epoch_sha256']
            fresh = isinstance(data.get('sample_time'), (int, float)) and data['sample_time'] >= completed_at
            counters_recorded = all(stored[key] >= native[key] for key in ('up_bytes', 'down_bytes'))
            checks.append({'port': account['port'], 'protocol': source,
                'native_source_readable': True, 'process_epoch_matches': epoch_matches,
                'normal_sample_fresh': fresh, 'native_bytes_recorded': counters_recorded,
                'monthly_delta_recorded': recorded})
    return checks


def run(report_path=None):
    separate_report = report_path is not None
    report_path = helpers.FOLDER / Path(report_path) if separate_report else REPORT
    helpers.require(not separate_report or not (report_path.exists() or report_path.is_symlink()),
                    'The requested acceptance report already exists')
    report = {'success': False, 'checked_at': datetime.now(timezone.utc).isoformat(),
        'configuration_changes': 0, 'credential_changes': 0, 'exit_changes': 0,
        'speed_or_load_tests': 0, 'web_logins': 0, 'samples': [], 'physical_wlan': True,
        'statistics_method': 'Read-only native APIs and fresh persisted samples; no web session.'}
    directory = benchmark.TEMP_ROOT / secrets.token_hex(8)
    isolated = ssh = sftp = None
    phase = 'private-temporary-directory'
    try:
        helpers.require(helpers.BINARY.is_file(), 'Official Mihomo is unavailable')
        helpers.require(not benchmark.TEMP_ROOT.is_symlink(), 'Unsafe private temporary parent')
        report['temporary_acl'] = benchmark.make_private(directory)
        phase = 'read-current-accounts'
        ssh = helpers.connect()
        sftp = ssh.open_sftp()
        accounts, before = helpers.collect_accounts(sftp)
        protected_before = protected(sftp, accounts)
        month = datetime.now(timezone.utc).strftime('%Y-%m')
        nodes = []
        for account in accounts:
            for source in ('hy2', 'xray'):
                node = copy.deepcopy(account['nodes'][source])
                node.update(name=source + '-' + str(account['port']), udp=False)
                nodes.append(node)
        phase = 'isolated-client-start'
        isolated = helpers.IsolatedClient(directory, nodes)
        isolated.start()
        native_after = {}
        minimums = {account['id']: {'up_bytes': 0, 'down_bytes': 0} for account in accounts}
        phase = 'six-public-exit-requests'
        for account in accounts:
            for source in ('hy2', 'xray'):
                original = native_snapshot(ssh, account, source)
                isolated.select(source + '-' + str(account['port']))
                response = isolated.curl(['https://api.ipify.org'], timeout=12)
                observed = str(ipaddress.ip_address(response.stdout.decode('ascii').strip())) if response.returncode == 0 else None
                final = native_snapshot(ssh, account, source)
                delta = helpers.counter_delta(original, final)
                verified = response.returncode == 0 and observed == account['expected_ip']
                incremented = all(value > 0 for value in delta.values())
                report['samples'].append({'port': account['port'], 'protocol': source,
                    'public_exit_verified': verified, 'native_counter_incremented': incremented,
                    'native_counter_delta': delta, 'expected_ip': account['expected_ip'], 'observed_ip': observed})
                helpers.require(verified and incremented, 'External exit or native transport increment did not verify')
                native_after[(account['id'], source)] = final
                for key, value in delta.items():
                    minimums[account['id']][key] += value
        isolated.close()
        code, output, unused_error = helpers.execute(ssh, 'python3 -c ' + shlex.quote(
            'import time; print(time.time())'), timeout=8)
        helpers.require(code == 0, 'Server sample timestamp is unavailable')
        completed_at = float(output.strip())
        phase = 'normal-ledger-tick'
        deadline = time.monotonic() + 35
        while True:
            helpers.require(datetime.now(timezone.utc).strftime('%Y-%m') == month,
                            'Acceptance crossed a UTC billing month')
            after = helpers.ledger(sftp)
            checks = ledger_checks(before, after, accounts, month, native_after, completed_at, minimums)
            if all(all(value is True for key, value in row.items() if key not in ('port', 'protocol')) for row in checks):
                break
            helpers.require(time.monotonic() < deadline, 'Fresh native-compatible ledger samples did not arrive')
            time.sleep(2)
        phase = 'preserved-account-settings'
        current_accounts, current_store = helpers.collect_accounts(sftp)
        helpers.require({item['port']: item['settings_hash'] for item in accounts} ==
                        {item['port']: item['settings_hash'] for item in current_accounts}, 'Account settings changed')
        helpers.require(protected(sftp, current_accounts) == protected_before, 'Protected account files changed')
        for account in accounts:
            for source in ('hy2', 'xray'):
                final = native_snapshot(ssh, account, source)
                helpers.counter_delta(native_after[(account['id'], source)], final)
        report.update(success=True, source_checks=checks, sources_verified=6,
            public_exit_requests=6, settings_preserved=True, limits_preserved=True,
            protected_files_preserved=True, monthly_totals_non_decreasing=True,
            no_transport_restarts_during_acceptance=True)
    except Exception as error:
        report.update(success=False, failure_phase=phase, error_type=type(error).__name__)
    finally:
        if isolated is not None:
            isolated.close()
        if sftp is not None:
            sftp.close()
        if ssh is not None:
            ssh.close()
        helpers.require(directory.resolve().parent == benchmark.TEMP_ROOT.resolve()
            and not directory.is_symlink() and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe private cleanup path')
        if directory.exists():
            shutil.rmtree(str(directory))
        report.update(temporary_private_files_removed=not directory.exists(),
            own_client_process_terminated=isolated is None or isolated.process is None or isolated.process.poll() is not None)
        with report_path.open('x' if separate_report else 'w', encoding='utf-8') as stream:
            stream.write(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--report', type=Path,
                        help='Separate report filename relative to this deployment; refuses overwrite.')
    args = parser.parse_args()
    result = run(args.report)
    print(json.dumps(result, ensure_ascii=True))
    raise SystemExit(0 if result.get('success') else 1)
