"""Publish one AUTO health-check generator and refresh existing full profiles.

Root-only Python 3.6 transaction; only the panel worker restarts. Credentials,
drafts, history, rule capabilities, Xray/HY2 epochs and the live ledger survive.
"""
import argparse
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

import optimize_udp_buffers_remote as m

FILES = ('panel/accelerated_client.py', 'panel/test_accelerated_client.py')
METADATA = {'profile', 'profile_version', 'profile_hash', 'profile_updated'}
FORMAT = 'vps-hy2-auto-health-v1'


def safe_stage(value):
    path = Path(value)
    m.require(path.is_absolute() and path.parent == Path('/root') and not path.is_symlink()
              and path.name.startswith('vps-hy2-auto-health-20261010-'), 'Unexpected private publication stage')
    m.require(path.is_dir() and path.stat().st_uid == 0 and stat.S_IMODE(path.stat().st_mode) == 0o700,
              'Private publication stage permissions differ')
    return path


def compare(baseline, context, expected, panel_running):
    value = copy.deepcopy(baseline)
    for path, digest in expected.items():
        if path in value['files']:
            value['files'][path]['sha256'] = digest
        m.require(m.sha(path) == digest, 'Publication destination changed concurrently')
    for record in value['records']:
        if record['state'] in expected:
            state = json.loads(m.safe_file(record['state']).read_text(encoding='utf-8'))
            value['applied_hashes'][str(record['port'])] = m.digest_json({key: item for key, item in state.items()
                if key.startswith('applied_') or key in ('active_id', 'profile', 'profile_hash', 'profile_version')})
    current = m.identity(context)
    m.compare_identity(value, current, panel_running)
    for name, status in baseline['services'].items():
        if name != m.PANEL:
            m.require(current['services'][name] == status, 'An unrelated service or proxy epoch changed')


def restore(entries):
    for item in reversed(entries):
        path = m.safe_file(item['path'])
        digest = m.sha(path)
        m.require(digest in (item['before_sha256'], item['after_sha256']),
                  'Concurrent publication edits prevent automatic rollback')
        if digest != item['before_sha256']:
            original = m.safe_file(item['backup']).read_bytes()
            m.require(m.sha(item['backup']) == item['before_sha256'], 'Private original differs')
            m.atomic(path, original, item['attributes'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True)
    parser.add_argument('--package-root', required=True)
    args = parser.parse_args()
    m.require(os.name == 'posix' and os.geteuid() == 0, 'Root Linux publication process is required')
    stage = safe_stage(args.stage)
    manifest = json.loads(m.safe_file(stage / 'manifest.json').read_text(encoding='utf-8'))
    m.require(manifest.get('format') == FORMAT and manifest.get('files') == list(FILES),
              'Unexpected frozen publication manifest')
    for name in FILES:
        path = m.safe_file(stage / 'release' / name)
        m.require(m.sha(path) == manifest['source_sha256'][name], 'Frozen generator or tests changed')
        compile(path.read_bytes(), name, 'exec')
    context = m.launch_context(Path(args.package_root))
    m.import_package(context)
    baseline = m.identity(context)
    m.require(m.active(baseline['services'][m.PANEL]), 'Panel writer must be active before publication')
    target = Path(context['package_root'])
    for name in FILES:
        m.require(m.sha(m.safe_file(target / name)) == manifest['baseline_sha256'][name],
                  'Deployed generator baseline changed concurrently')
    m.require(not m.LOCK.is_symlink(), 'Unsafe shared maintenance lock')
    fd = os.open(str(m.LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    entries, installed, expected = [], [], {}
    stopped = False
    result = {'success': False, 'scope': 'AUTO health check and existing full-profile refresh',
              'phase': 'preflight', 'stage': str(stage), 'transport_restarts': 0,
              'traffic_ledger_restored': False}
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = stage / 'before'
        m.require(not before.exists(), 'Publication stage has already been used')
        before.mkdir(mode=0o700)
        before_ledger = m.ledger(context)
        qdisc = m.qdisc_snapshot()['semantic_sha256']
        sysctls = m.sysctls()
        result['phase'] = 'stop-panel-writer'
        m.run(['systemctl', 'stop', m.PANEL])
        stopped = True
        compare(baseline, context, {str(target / name): manifest['baseline_sha256'][name] for name in FILES}, False)
        accounts, integration, traffic = m.traffic_context(context)
        for record in baseline['records']:
            if record['enabled']:
                m.sample(traffic, record['id'])
        m.check_ledger(before_ledger, m.ledger(context))
        result['latest_native_flow_persisted'] = True
        spec = importlib.util.spec_from_file_location('reviewed_auto_health', str(stage / 'release/panel/accelerated_client.py'))
        candidate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(candidate)
        from panel.subscriptions import update_metadata
        mutations = []
        for record in baseline['records']:
            state_path = m.safe_file(record['state'])
            original = json.loads(state_path.read_text(encoding='utf-8'))
            m.require(isinstance(original.get('profile'), str) and original['profile'],
                      'The adopted full client profile is unavailable')
            credentials = integration.data['accounts'][record['id']]
            updated = copy.deepcopy(original)
            updated['profile'] = candidate.compose(original['profile'], context['public_ip'], record['port'],
                credentials['password'], integration.data['certificate_sha256'], integration.data['sni'])
            update_metadata(updated, original)
            m.require({key: value for key, value in updated.items() if key not in METADATA}
                      == {key: value for key, value in original.items() if key not in METADATA},
                      'Account credentials, settings, drafts, capabilities or history changed')
            m.require(updated['profile'] == candidate.compose(updated['profile'], context['public_ip'],
                record['port'], credentials['password'], integration.data['certificate_sha256'], integration.data['sni']),
                'Refreshed profile is not idempotent')
            mutations.append((state_path, (json.dumps(updated, ensure_ascii=False, indent=2) + '\n').encode('utf-8')))
        mutations += [(target / name, (stage / 'release' / name).read_bytes()) for name in FILES]
        for path, data in mutations:
            m.safe_file(path)
            original = path.read_bytes()
            info = m.attributes(path)
            backup = before / (str(len(entries)) + '.private')
            m.atomic(backup, original)
            entries.append({'path': str(path), 'backup': str(backup), 'attributes': info,
                'before_sha256': m.sha(path), 'after_sha256': hashlib.sha256(data).hexdigest()})
            expected[str(path)] = entries[-1]['before_sha256']
        m.private_json(stage / 'transaction.private.json', {'format': FORMAT, 'entries': entries, 'installed': []})
        compare(baseline, context, expected, False)
        result['phase'] = 'install-frozen-generator-and-profiles'
        for (path, data), entry in zip(mutations, entries):
            m.require(m.sha(path) == entry['before_sha256'], 'Destination changed before installation')
            installed.append(entry)
            m.private_json(stage / 'transaction.private.json', {'format': FORMAT, 'entries': entries, 'installed': installed})
            m.atomic(path, data, entry['attributes'])
            expected[str(path)] = entry['after_sha256']
        compare(baseline, context, expected, False)
        m.check_ledger(before_ledger, m.ledger(context))
        m.require(m.qdisc_snapshot()['semantic_sha256'] == qdisc and m.sysctls() == sysctls,
                  'Network queue or buffer settings changed')
        result['phase'] = 'start-panel-writer'
        m.run(['systemctl', 'start', m.PANEL])
        m.wait_panel(context)
        compare(baseline, context, expected, True)
        m.check_ledger(before_ledger, m.ledger(context))
        result.update(success=True, phase='complete', profiles_refreshed=len(baseline['records']),
                      account_settings_preserved=True, credentials_preserved=True, drafts_history_preserved=True,
                      full_subscription_tokens_preserved=True, proxy_epochs_preserved=True,
                      ledger_totals_non_decreasing=True, only_panel_restarted=True,
                      panel_session_notice='Panel worker restarted; browser sessions require login again.',
                      client_refresh_required=True, health_check={'url':'https://www.gstatic.com/generate_204',
                          'expected-status':'204','interval':30,'timeout':5000,'lazy':False})
    except BaseException as error:
        result.update(success=False, error_type=type(error).__name__,
                      failure=str(error) if isinstance(error, RuntimeError) else 'Publication did not complete')
        try:
            m.require(stopped, 'Publication stopped before service maintenance')
            if m.active(m.service(m.PANEL)):
                m.run(['systemctl', 'stop', m.PANEL])
            restore(installed)
            m.check_ledger(before_ledger, m.ledger(context))
            expected = {entry['path']: entry['before_sha256'] for entry in entries}
            compare(baseline, context, expected, False)
            result['rollback_success'] = True
        except BaseException:
            result['rollback_success'] = False
        finally:
            try:
                if stopped:
                    m.run(['systemctl', 'start', m.PANEL])
                    m.wait_panel(context)
                    result['panel_ready'] = True
            except BaseException:
                result['panel_ready'] = False
    finally:
        os.close(fd)
        m.private_json(stage / 'report.json', result)
    return result


if __name__ == '__main__':
    try:
        result = main()
    except BaseException as error:
        result = {'success': False, 'error_type': type(error).__name__,
                  'failure': str(error) if isinstance(error, RuntimeError) else 'Publication failed before its transaction'}
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    raise SystemExit(0 if result.get('success') else 1)
