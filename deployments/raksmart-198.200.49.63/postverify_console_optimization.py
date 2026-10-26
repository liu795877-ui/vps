"""Read-only delayed production verification against a successful checkpoint.

Default verifies local public package/report/helper evidence without SSH.
--run reads production files and kernel/service observations only. It uses no
account login, uploads no files, starts no jobs, and saves its report locally.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

import deploy_console_optimization as deployment
import validate_console_optimization as validator

FOLDER = Path(__file__).resolve().parent
REPORT_NAME = 'console-optimization-post-deployment-verification-20261013.json'
DEPLOYMENT_REPORT = 'console-optimization-deployment-20261013-02.json'


REMOTE_PROGRAM = r'''
import hashlib, importlib.util, json, os, re, stat, sys
from datetime import datetime, timezone
from pathlib import Path
sys.dont_write_bytecode = True
configuration = CONFIGURATION_LITERAL
result = {'success': False, 'scope': 'read-only delayed production verification',
          'production_updated': False, 'service_control_performed': False,
          'account_login_performed': False, 'functional_tests_repeated': False}
phase = 'checkpoint-helper-identity'
try:
    def require(value, message):
        if not value:
            raise RuntimeError(message)
    require(sys.version_info[:2] == (3, 6) and os.geteuid() == 0, 'Unexpected host runtime')
    require(re.fullmatch(r'/root/vps-console-deploy-[A-Za-z0-9_-]+', configuration['stage']), 'Unexpected checkpoint path')
    stage = Path(configuration['stage'])
    require(stage.is_dir() and not any(part.is_symlink() for part in [stage] + list(stage.parents))
            and stage.stat().st_uid == 0 and stat.S_IMODE(stage.stat().st_mode) == 0o700, 'Checkpoint boundary differs')
    helper_path = stage / 'deploy_remote.py'
    require(helper_path.is_file() and not helper_path.is_symlink() and stat.S_ISREG(helper_path.stat().st_mode),
            'Checkpoint helper is not a regular file')
    require(hashlib.sha256(helper_path.read_bytes()).hexdigest() == configuration['helper_sha256'],
            'Checkpoint helper differs from the reviewed deployed helper')
    spec = importlib.util.spec_from_file_location('reviewed_console_checkpoint_observers', str(helper_path))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    phase = 'completed-checkpoint-evidence'
    report = json.loads(helper.safe(stage / 'report.json', True).read_text(encoding='utf-8'))
    require(report.get('success') is True and report.get('production_updated') is True
            and report.get('phase') == 'complete' and report.get('archive_sha256') == configuration['archive_sha256'],
            'Checkpoint does not describe the intended successful deployment')
    journal = json.loads(helper.safe(stage / 'transaction.private.json', True).read_text(encoding='utf-8'))
    require(journal.get('phase') == 'complete' and journal.get('archive_sha256') == configuration['archive_sha256']
            and journal.get('release_sha256') == configuration['release_sha256'], 'Completed source index differs')
    helper.validate_journal(stage, journal)
    phase = 'protected-snapshot'
    before = json.loads(helper.safe(stage / 'protected-before.private.json', True).read_text(encoding='utf-8'))
    after = helper.snapshot()
    helper.compare_snapshot(before, after, True)
    require(len(before['records']) == len(after['records']) == 3
            and all(record['enabled'] for record in after['records']), 'Adopted three-account registry differs')
    require(after['services'][helper.PANEL]['ActiveState'] == 'active', 'Panel is not active')
    phase = 'traffic-cumulative'
    before_ledger = json.loads(helper.safe(stage / 'ledger-before.private.json', True).read_text(encoding='utf-8'))
    helper.compare_ledger(before_ledger, helper.ledger())
    phase = 'frozen-application-source'
    require(len(journal['release_sha256']) == 41, 'Unexpected deployed source count')
    for name, expected in journal['release_sha256'].items():
        helper.source_name(name)
        require(helper.sha(helper.safe(helper.APP / name, True).read_bytes()) == expected, 'Managed source changed')
    phase = 'unused-entrance-and-task-stores'
    for name in ('entrance-pool.private.json', 'member-tasks.private.json'):
        path = str(helper.DATA / name)
        require(before['files'][path] == after['files'][path] == {'exists': False}, 'Previously absent store appeared')
    result.update(success=True, phase='complete', verified_at=datetime.now(timezone.utc).isoformat(),
                  archive_sha256=configuration['archive_sha256'], helper_sha256=configuration['helper_sha256'],
                  source_files_verified=len(journal['release_sha256']), account_count=3,
                  protected_bytes_preserved=True, proxy_epochs_preserved=True,
                  panel_active=True, panel_enablement_preserved=True, network_policy_preserved=True,
                  traffic_cumulative_non_decreasing=True, entrance_pool_still_absent=True,
                  member_task_store_still_absent=True, account_registry_and_profiles_preserved=True,
                  bytecode_writes_disabled=sys.dont_write_bytecode)
except BaseException as error:
    result.update(phase=phase, error_type=type(error).__name__, failure='Read-only verification did not pass')
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result.get('success') else 1)
'''


def review(deployment_report):
    report = json.loads(deployment.safe_file(deployment_report).read_text(encoding='utf-8'))
    verification = report.get('verification', {})
    deployment.require(report.get('success') is True and verification.get('success') is True
                       and report.get('production_updated') is True and verification.get('phase') == 'complete',
                       'A successful completed deployment report is required')
    stage = report.get('remote_stage')
    deployment.require(isinstance(stage, str) and re.fullmatch(r'/root/vps-console-deploy-[A-Za-z0-9_-]+', stage),
                       'Unexpected retained checkpoint')
    candidate = validator.local_review('console-optimization-release-20261013-05')
    helper = deployment.safe_file(FOLDER / 'deploy_console_optimization_remote.py').read_bytes()
    helper_hash = hashlib.sha256(helper).hexdigest()
    deployment.require(helper_hash == report.get('remote_helper_sha256')
                       and candidate['archive_sha256'] == report.get('archive_sha256')
                       and candidate['manifest_sha256'] == report.get('manifest_sha256'),
                       'Local package/helper no longer match the deployed frozen baseline')
    configuration = {'stage': stage, 'helper_sha256': helper_hash, 'archive_sha256': candidate['archive_sha256'],
                     'release_sha256': candidate['release_sha256']}
    program = REMOTE_PROGRAM.replace('CONFIGURATION_LITERAL', repr(configuration), 1)
    ast.parse(program, feature_version=(3, 6))
    return configuration, program


def run(configuration, program, report_path):
    import ssh_access as ssh
    deployment.require(not report_path.exists() and not report_path.is_symlink(), 'Post-verification report already exists')
    client = validator.strict_connect(ssh)
    result = {'success': False, 'started_at': datetime.now(timezone.utc).isoformat(),
              'archive_sha256': configuration['archive_sha256'], 'remote_helper_sha256': configuration['helper_sha256'],
              'remote_stage': configuration['stage'], 'report': str(report_path), 'production_updated': False}
    try:
        code, output, unused_error = ssh.execute(client, validator.remote_command(program), timeout=150)
        deployment.require(bool(output.strip()), 'Read-only verification returned no summary')
        verification = json.loads(output.strip().splitlines()[-1])
        result.update(remote_exit_code=code, verification=verification,
                      success=code == 0 and verification.get('success') is True)
    except Exception as error:
        result.update(error_type=type(error).__name__, failure='Read-only verification did not complete')
    finally:
        client.close()
        with report_path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deployment-report', default=str(FOLDER / DEPLOYMENT_REPORT))
    parser.add_argument('--report-name', default=REPORT_NAME)
    parser.add_argument('--run', action='store_true', help='Read production state and save the local verification report')
    args = parser.parse_args()
    deployment.require(re.fullmatch(r'console-optimization-post-deployment-verification-[A-Za-z0-9_-]+\.json', args.report_name),
                       'Unexpected local report name')
    configuration, program = review(args.deployment_report)
    if not args.run:
        print(json.dumps({'local_review_passed': True, 'remote_connected': False, 'production_updated': False,
                          'remote_stage': configuration['stage'], 'helper_sha256': configuration['helper_sha256'],
                          'source_files': len(configuration['release_sha256']), 'explicit_run_required': True}, indent=2))
        return 0
    result = run(configuration, program, FOLDER / args.report_name)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, SyntaxError) as error:
        print('Read-only verification review stopped: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
