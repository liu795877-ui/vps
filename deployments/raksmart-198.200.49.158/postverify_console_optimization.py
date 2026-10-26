"""Read-only delayed verification of the successful .158 adoption checkpoint."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

import deploy_console_optimization as deployment
import validate_console_optimization as validator

FOLDER = Path(__file__).resolve().parent
REMOTE = r'''
import hashlib, importlib.util, json, os, stat, sys
from pathlib import Path
sys.dont_write_bytecode = True
configuration = CONFIGURATION_LITERAL
result = {'success': False, 'production_updated': False,
          'service_control_performed': False, 'account_login_performed': False,
          'scope': 'read-only delayed adoption verification', 'secrets_included': False}
phase = 'checkpoint-identity'
try:
    def require(value, message):
        if not value: raise RuntimeError(message)
    stage = Path(configuration['stage'])
    require(sys.version_info[:2] == (3, 6) and os.geteuid() == 0, 'Unexpected host runtime')
    require(stage.is_dir() and not any(path.is_symlink() for path in [stage] + list(stage.parents))
            and stage.stat().st_uid == 0 and stat.S_IMODE(stage.stat().st_mode) == 0o700, 'Checkpoint boundary differs')
    helper_file = stage / 'deploy_remote.py'
    require(helper_file.is_file() and not helper_file.is_symlink()
            and hashlib.sha256(helper_file.read_bytes()).hexdigest() == configuration['helper_sha256'], 'Deployed helper differs')
    spec = importlib.util.spec_from_file_location('reviewed_adoption_observers', str(helper_file))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    journal = json.loads(helper.safe(stage / 'transaction.private.json', True).read_text())
    completed = json.loads(helper.safe(stage / 'report.json', True).read_text())
    require(journal.get('phase') == 'complete' and completed.get('success') is True
            and completed.get('production_updated') is True, 'Checkpoint does not describe completed adoption')
    require(journal['configuration']['archive_sha256'] == configuration['archive_sha256']
            and journal['configuration']['release_sha256'] == configuration['release_sha256'], 'Frozen source checkpoint differs')
    phase = 'frozen-application-and-dependencies'
    require(len(configuration['release_sha256']) == 41, 'Unexpected application inventory')
    for name, expected in configuration['release_sha256'].items():
        helper.source_name(name)
        require(helper.sha(helper.safe(helper.APP / name, True).read_bytes()) == expected, 'Application source changed')
    for name, expected in configuration['vendor_sha256'].items():
        helper.vendor_name('vendor/' + name)
        require(helper.sha(helper.safe(helper.APP / 'vendor' / name, True).read_bytes()) == expected, 'Dependency source changed')
    for entry in journal['entries']:
        require(helper.observation(entry['path']).get('sha256') == entry['after_sha256'], 'Migrated file changed')
    phase = 'account-and-node-identity'
    state_entry = next(entry for entry in journal['entries'] if entry['path'] == str(helper.DATA / 'state.private.json'))
    old_state = json.loads(helper.safe(stage / state_entry['backup'], True).read_text())
    state = json.loads(helper.safe(helper.DATA / 'state.private.json', True).read_text())
    helper.state_preserved(old_state, state)
    require(state['managed_hash'] == helper.sha(helper.safe(helper.XRAY_CONFIG, True).read_bytes()), 'State/config binding differs')
    users = json.loads(helper.safe(helper.DATA / 'users.private.json', True).read_text())
    registry = json.loads(helper.safe(helper.DATA / 'hy2.private.json', True).read_text())
    require(not users['users'] and set(registry['accounts']) == {'admin'}, 'Preserved administrator allocation differs')
    require(registry['accounts']['admin']['password'] == helper.legacy_values(helper.safe(helper.HY2_ROOT / 'server.yaml', True).read_bytes())
            and registry['certificate_sha256'] == configuration['certificate_sha256'], 'Original HY2 authentication differs')
    for name in ['crt', 'key']:
        require(helper.safe(helper.DATA / ('hy2-server.' + name + '.pem'), True).read_bytes()
                == helper.safe(helper.HY2_ROOT / ('server.' + name + '.pem'), True).read_bytes(), 'TLS identity copy differs')
    phase = 'stable-production-snapshot'
    expected = json.loads(helper.safe(stage / 'protected-after.private.json', True).read_text())
    current = helper.protected_snapshot()
    require(expected == current, 'Protected bytes, service process epochs or network policy changed')
    hy2 = helper.service(helper.OWNER_HY2)
    require(hy2.get('ActiveState') == 'active' and hy2.get('UnitFileState') == 'enabled', 'Adopted HY2 service is unhealthy')
    require(helper.service(helper.LEGACY).get('ActiveState') == 'inactive'
            and helper.service(helper.LEGACY).get('UnitFileState') == 'disabled', 'Legacy service returned')
    phase = 'cumulative-traffic'
    ledger = json.loads(helper.safe(stage / 'ledger-post-deployment.private.json', True).read_text())
    helper.compare_ledger(ledger, helper.ledger())
    for name in ['entrance-pool.private.json', 'member-tasks.private.json']:
        require(not helper.safe(helper.DATA / name, True, True).exists(), 'Previously unused pool or task store appeared')
    result.update(success=True, phase='complete', source_files_verified=41,
                  dependency_files_verified=len(configuration['vendor_sha256']),
                  original_accounts_and_identities_preserved=True, original_hy2_password_and_tls_preserved=True,
                  protected_bytes_and_network_preserved=True, service_epochs_preserved=True,
                  traffic_cumulative_non_decreasing=True, unused_member_stores_absent=True,
                  current_target_preserved=True, bytecode_writes_disabled=True)
except BaseException as error:
    result.update(phase=phase, error_type=type(error).__name__, failure='Delayed read-only verification did not pass')
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result['success'] else 1)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment-report', default=str(FOLDER / 'console-optimization-deployment-20261013-01.json'))
    parser.add_argument('--report-name', default='console-optimization-post-deployment-verification-20261013.json')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    report = json.loads(deployment.safe_file(args.deployment_report).read_text())
    deployment.require(report.get('success') is True and report.get('production_updated') is True
                       and report.get('verification', {}).get('phase') == 'complete', 'Completed successful deployment required')
    reviewed = validator.local_review('console-optimization-release-20261013-01')
    helper_sha256 = hashlib.sha256(deployment.safe_file(FOLDER / 'deploy_console_optimization_remote.py').read_bytes()).hexdigest()
    deployment.require(helper_sha256 == report['remote_helper_sha256']
                       and reviewed['archive_sha256'] == report['archive_sha256']
                       and reviewed['manifest_sha256'] == report['manifest_sha256'], 'Deployed source or helper differs')
    stage = report['remote_stage']
    deployment.require(re.fullmatch(r'/root/vps-console-adoption-[A-Za-z0-9_-]+', stage), 'Unexpected checkpoint path')
    configuration = {'stage': stage, 'helper_sha256': helper_sha256, 'archive_sha256': reviewed['archive_sha256'],
                     'release_sha256': reviewed['release_sha256'], 'vendor_sha256': reviewed['vendor_sha256'],
                     'certificate_sha256': json.loads(deployment.safe_file(FOLDER / 'console-optimization-preflight-20261013.json').read_text())['legacy_hy2']['certificate_sha256']}
    program = REMOTE.replace('CONFIGURATION_LITERAL', repr(configuration), 1)
    ast.parse(program, feature_version=(3, 6))
    if not args.run:
        print(json.dumps({'local_review_passed': True, 'remote_connected': False, 'production_updated': False}))
        return 0
    deployment.require(re.fullmatch(r'console-optimization-post-deployment-verification-[A-Za-z0-9_-]+\.json', args.report_name), 'Unexpected report name')
    output = FOLDER / args.report_name
    deployment.require(not output.exists(), 'Postverification report already exists')
    import ssh_access as ssh
    client = validator.strict_connect(ssh)
    result = {'success': False, 'checked_at': datetime.now(timezone.utc).isoformat(), 'server': '198.200.49.158',
              'remote_stage': stage, 'remote_helper_sha256': helper_sha256, 'production_updated': False}
    try:
        code, value, unused_error = ssh.execute(client, validator.remote_command(program), timeout=180)
        verification = json.loads(value.strip().splitlines()[-1])
        result.update(verification=verification, success=code == 0 and verification.get('success') is True)
    except Exception as error:
        result.update(error_type=type(error).__name__, failure='Delayed verification did not complete')
    finally:
        client.close()
        output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
