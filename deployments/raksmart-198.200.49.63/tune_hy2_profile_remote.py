"""Root-only, per-instance BBR trials; private checkpoints never include traffic.

Reuse the adopted host's UDP maintenance lifecycle. Final business counters
are persisted before restart; the non-atomic sample-to-stop tail remains.
Only the selected HY2 runtime configuration may change, and only two BBR keys.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time

import optimize_udp_buffers_remote as m

FORMAT = 'vps-hy2-bbr-trials-v1'
PROFILES = ('standard', 'conservative', 'aggressive')


def config_path(port):
    return Path('/usr/local/etc/raksmart-hy2/accounts/' + str(port) + '.yaml')


def config(data):
    value = json.loads(data.decode('utf-8'))
    m.require(isinstance(value, dict) and isinstance(value.get('congestion'), dict)
              and value['congestion'].get('type') == 'bbr'
              and value['congestion'].get('bbrProfile') in PROFILES,
              'The adopted JSON-valid YAML BBR configuration is unavailable')
    return value


def unchanged_fields(value):
    result = copy.deepcopy(value)
    result['congestion'].pop('type', None)
    result['congestion'].pop('bbrProfile', None)
    return result


def official(record):
    status = m.service(record['hy2'])
    m.require(record['enabled'] and m.active(status) and int(status['MainPID']) > 0,
              'The selected enabled HY2 instance must be active')
    process = Path('/proc/' + status['MainPID'])
    args = (process / 'cmdline').read_bytes().decode('utf-8').rstrip('\0').split('\0')
    m.require((process / 'exe').resolve() == Path('/usr/local/bin/raksmart-hysteria2')
              and args[1:] == ['server', '--config', str(config_path(record['port']))],
              'The selected process is not the adopted official HY2 instance')
    m.require(str(record['port']) in m.sockets(), 'Selected public UDP socket is absent')


def protected(baseline, current, port, expected_sha, panel_running):
    expected = copy.deepcopy(baseline)
    expected['files'][str(config_path(port))]['sha256'] = expected_sha
    m.compare_identity(expected, current, panel_running)
    for name, before in baseline['services'].items():
        if name.startswith('raksmart-hy2@') and name != 'raksmart-hy2@' + str(port) + '.service':
            m.require(current['services'][name] == before, 'Another HY2 instance changed epoch')


def checkpoint(value, create):
    path = Path(value)
    m.require(path.is_absolute() and path.parent == Path('/root') and not path.is_symlink()
              and path.name.startswith('vps-hy2-bbr-20261010-'), 'Invalid private BBR checkpoint path')
    if create:
        m.require(not path.exists(), 'Private checkpoint already exists')
        path.mkdir(mode=0o700)
    m.require(path.is_dir() and path.stat().st_uid == 0
              and stat.S_IMODE(path.stat().st_mode) == 0o700, 'Private checkpoint permissions differ')
    return path


def private_bytes(data, info):
    return {'data': base64.b64encode(data).decode('ascii'), 'attributes': info,
            'sha256': hashlib.sha256(data).hexdigest()}


def unpack(saved):
    data = base64.b64decode(saved['data'], validate=True)
    m.require(hashlib.sha256(data).hexdigest() == saved['sha256'], 'Private configuration checkpoint differs')
    config(data)
    return data


def synchronize(accounts, integration, traffic, record, before):
    started = time.time()
    m.run(['systemctl', 'restart', record['hy2']])
    m.wait_hy2(integration, accounts._record(record['id']))
    after = m.sample(traffic, record['id'])
    m.require(after['epoch'] != before['epoch'] and after['total_bytes'] >= before['total_bytes'],
              'HY2 restart epoch or cumulative accounting did not synchronize')
    return {'epoch_changed': True, 'total_bytes_non_decreasing': True,
            'business_counters_stable_before_restart': before['business_counters_stable_before_restart'],
            'tail_accounting_limitation': before['tail_accounting_limitation'],
            'sample_to_restart_request_ms': round((started - before['sample_completed_at_unix']) * 1000, 3)}


def change(context, journal, backup, action, data, info):
    port = journal['port']
    path = m.safe_file(config_path(port))
    before_data, before_info = path.read_bytes(), m.attributes(path)
    before_sha, after_sha = m.sha(path), hashlib.sha256(data).hexdigest()
    baseline = m.identity(context)
    protected(journal['identity'], baseline, port, journal['expected_sha256'], True)
    m.require(before_sha == journal['expected_sha256'], 'Runtime configuration changed concurrently')
    record = next(item for item in baseline['records'] if item['port'] == port)
    official(record)
    before_ledger = m.ledger(context)
    objects, attempted = None, False
    try:
        m.run(['systemctl', 'stop', m.PANEL])
        protected(baseline, m.identity(context), port, before_sha, False)
        objects = m.traffic_context(context)
        accounts, integration, traffic = objects
        m.require(unchanged_fields(config(before_data)) == unchanged_fields(
            integration.config(accounts._record(record['id'])))
            and unchanged_fields(config(data)) == unchanged_fields(config(before_data)),
            'A private credential, route or non-BBR setting differs')
        protected(baseline, m.identity(context), port, before_sha, False)
        journal['pending_sha256'] = after_sha
        m.private_json(backup / 'checkpoint.private.json', journal)
        final = m.prepare_restart(accounts, integration, traffic, record)
        m.require(m.sha(path) == before_sha, 'Runtime configuration changed before application')
        attempted = True
        m.atomic(path, data, info)
        restart = synchronize(accounts, integration, traffic, record, final)
        official(record)
        protected(baseline, m.identity(context), port, after_sha, False)
        m.check_ledger(before_ledger, m.ledger(context))
        m.run(['systemctl', 'start', m.PANEL])
        m.wait_panel(context)
        protected(baseline, m.identity(context), port, after_sha, True)
        m.check_ledger(before_ledger, m.ledger(context))
        journal.update(expected_sha256=after_sha, pending_sha256=None)
        m.private_json(backup / 'checkpoint.private.json', journal)
        return {'success': True, 'action': action, 'port': port,
                'profile': config(data)['congestion']['bbrProfile'], 'runtime_sha256': after_sha,
                'other_instances_preserved': True, 'identity_preserved': True,
                'ledger_totals_non_decreasing': True, 'traffic_ledger_restored': False,
                'restart': restart, 'backup_dir': str(backup),
                'panel_session_notice': 'Panel sessions require login again after its worker restart.'}
    except BaseException as error:
        result = {'success': False, 'action': action, 'port': port,
                  'failure': str(error) if isinstance(error, RuntimeError) else 'BBR maintenance failed'}
        try:
            if m.active(m.service(m.PANEL)):
                m.run(['systemctl', 'stop', m.PANEL])
            objects = objects or m.traffic_context(context)
            accounts, integration, traffic = objects
            traffic.reload()
            m.require(m.sha(path) in (before_sha, after_sha), 'Concurrent configuration prevents rollback')
            if attempted:
                if m.active(m.service(record['hy2'])):
                    try:
                        final = m.prepare_restart(accounts, integration, traffic, record)
                    except Exception:
                        final = None  # The successful pre-trial final sample remains persisted.
                else:
                    final = None
                m.atomic(path, before_data, before_info)
                if final:
                    synchronize(accounts, integration, traffic, record, final)
                else:
                    m.run(['systemctl', 'restart', record['hy2']])
                    m.wait_hy2(integration, accounts._record(record['id']))
                    m.sample(traffic, record['id'])
            m.check_ledger(before_ledger, m.ledger(context))
            journal.update(expected_sha256=before_sha, pending_sha256=None)
            m.private_json(backup / 'checkpoint.private.json', journal)
            result['rollback'] = {'success': True, 'profile': config(before_data)['congestion']['bbrProfile'],
                                  'traffic_ledger_restored': False, 'ledger_totals_non_decreasing': True}
        except BaseException:
            result['rollback'] = {'success': False, 'failure': 'Host inspection is required'}
        finally:
            try:
                m.run(['systemctl', 'start', m.PANEL])
                m.wait_panel(context)
                result['panel_ready'] = True
                protected(baseline, m.identity(context), port, before_sha, True)
                result['rollback_identity_preserved'] = True
            except Exception:
                result.setdefault('panel_ready', False)
                result['rollback_identity_preserved'] = False
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', required=True, choices=('snapshot', 'set', 'restore'))
    parser.add_argument('--port', required=True, type=int, choices=m.PORTS)
    parser.add_argument('--profile', choices=PROFILES)
    parser.add_argument('--package-root', required=True)
    parser.add_argument('--backup-dir')
    args = parser.parse_args()
    m.require(os.name == 'posix' and os.geteuid() == 0, 'Root Linux maintenance process is required')
    context = m.launch_context(Path(args.package_root))
    m.import_package(context)
    baseline = m.identity(context)
    record = next(item for item in baseline['records'] if item['port'] == args.port)
    official(record)
    path = m.safe_file(config_path(args.port))
    current = config(path.read_bytes())
    if args.action == 'snapshot':
        return {'success': True, 'action': 'snapshot', 'port': args.port,
                'profile': current['congestion']['bbrProfile'], 'runtime_sha256': m.sha(path),
                'source_sha256': m.sha(Path(context['package_root']) / 'panel/hy2.py'),
                'binary_sha256': m.sha('/usr/local/bin/raksmart-hysteria2'), 'runtime': m.runtime_snapshot(context)}
    m.require(args.backup_dir and (args.action != 'set' or args.profile), 'Checkpoint and profile are required')
    m.require(not m.LOCK.is_symlink() and m.LOCK.parent.is_dir(), 'Unsafe maintenance lock')
    fd = os.open(str(m.LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        backup = checkpoint(args.backup_dir, not Path(args.backup_dir).exists() and args.action == 'set')
        journal_path = backup / 'checkpoint.private.json'
        if journal_path.exists():
            m.safe_file(journal_path)
            m.require(journal_path.stat().st_uid == 0 and stat.S_IMODE(journal_path.stat().st_mode) == 0o600,
                      'Private checkpoint metadata permissions differ')
            journal = json.loads(journal_path.read_text())
            m.require(journal.get('format') == FORMAT and journal.get('context') == context
                      and journal.get('port') == args.port, 'Checkpoint belongs to a different target')
            m.require(journal.get('pending_sha256') is None, 'Interrupted maintenance requires host inspection')
        else:
            m.require(args.action == 'set', 'The original configuration checkpoint is absent')
            journal = {'format': FORMAT, 'context': context, 'port': args.port, 'identity': baseline,
                       'original': private_bytes(path.read_bytes(), m.attributes(path)),
                       'expected_sha256': m.sha(path), 'pending_sha256': None}
            m.private_json(journal_path, journal)
        protected(journal['identity'], m.identity(context), args.port, journal['expected_sha256'], True)
        if args.action == 'restore':
            data, info = unpack(journal['original']), journal['original']['attributes']
        else:
            current['congestion'].update(type='bbr', bbrProfile=args.profile)
            data = (json.dumps(current, sort_keys=True, indent=2) + '\n').encode('utf-8')
            info = m.attributes(path)
        return change(context, journal, backup, args.action, data, info)
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        result = main()
    except BaseException as error:
        result = {'success': False, 'failure': str(error) if isinstance(error, RuntimeError) else 'BBR maintenance failed'}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    raise SystemExit(0 if result.get('success') else 1)
