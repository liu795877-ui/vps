"""Review or explicitly deploy a validated frozen .63 console source package.

Default is local review only. --run uploads one source archive and a reviewed
Python 3.6 transaction. Login credentials are sent once over SSH stdin and are
never uploaded, printed, placed in command arguments, or saved in reports.
Only the remote helper may restart vps-panel.service; no installer is called.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys

import stage_console_optimization as staging
import validate_console_optimization as validator

FOLDER = Path(__file__).resolve().parent
REMOTE_HELPER = FOLDER / 'deploy_console_optimization_remote.py'
DEFAULT_LOGIN_FILES = ('panel-login.private.json', 'multiuser-user-a-login.private.json',
                       'multiuser-user-b-login.private.json')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def safe_file(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'Absolute canonical local input required')
    require(all(not item.is_symlink() for item in [path] + list(path.parents)), 'Linked local input rejected')
    require(path.parent.resolve() == FOLDER and path.is_file(), 'Input must be a regular file in the .63 folder')
    return path


def review(release_directory, validation_path, baseline_directory=None):
    directory = Path(release_directory)
    require(directory.is_absolute() and not directory.is_symlink() and directory.resolve().parent == FOLDER,
            'Use an absolute frozen release path in the .63 folder')
    result = validator.local_review(directory.name)
    manifest_path = directory / 'manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    validation = json.loads(safe_file(validation_path).read_text(encoding='utf-8'))
    checks = validation.get('verification', {})
    require(validation.get('success') is True and validation.get('release_tests_run') is True
            and validation.get('archive_sha256') == result['archive_sha256']
            and validation.get('manifest_sha256') == result['manifest_sha256']
            and validation.get('environment', {}).get('python_version', [])[:2] == [3, 6]
            and checks.get('success') is True and checks.get('failures') == 0 and checks.get('errors') == 0,
            'A successful actual Python 3.6 report for the exact candidate is required')
    baseline_label = 'frozen-hy2-plus-auto-production-baseline'
    if baseline_directory:
        baseline_path = Path(baseline_directory)
        require(baseline_path.is_absolute() and not baseline_path.is_symlink()
                and baseline_path.resolve().parent == FOLDER, 'Unexpected baseline release directory')
        baseline_review = validator.local_review(baseline_path.name)
        baseline = baseline_review['release_sha256']
        baseline_label = baseline_path.name
    else:
        unused, baseline = staging.load_baseline({})
        require(baseline == manifest.get('baseline_sha256'), 'Candidate baseline does not match the frozen production baseline')
    helper = safe_file(REMOTE_HELPER).read_bytes()
    ast.parse(helper.decode('utf-8'), filename=str(REMOTE_HELPER), feature_version=(3, 6))
    return dict(result, baseline_sha256=baseline, baseline_label=baseline_label,
                helper_sha256=sha(helper), helper=helper, validation_report=str(validation_path),
                manifest=manifest_path.read_bytes(),
                format=manifest['format'], deployment_ip=manifest['deployment_ip'])


def credentials(paths):
    result = []
    for path in paths:
        value = json.loads(safe_file(path).read_text(encoding='utf-8'))
        require(value.get('url') == 'https://198-200-49-63.sslip.io:8443/node-console/'
                and isinstance(value.get('username'), str) and isinstance(value.get('password'), str),
                'A local login belongs to another site or is malformed')
        result.append({'username': value['username'], 'password': value['password']})
    require(len({item['username'] for item in result}) == len(result), 'Repeated login username')
    return result


def run(reviewed, login_files, report_path, registry_preflight=False):
    import ssh_access as ssh
    require(not report_path.exists() and not report_path.is_symlink(), 'Deployment report already exists')
    client = validator.strict_connect(ssh)
    result = {'success': False, 'started_at': datetime.now(timezone.utc).isoformat(),
              'archive_sha256': reviewed['archive_sha256'], 'manifest_sha256': reviewed['manifest_sha256'],
              'remote_helper_sha256': reviewed['helper_sha256'], 'baseline': reviewed['baseline_label'],
              'local_report': str(report_path)}
    try:
        create = "import json,os,tempfile\np=tempfile.mkdtemp(prefix='vps-console-deploy-',dir='/root')\nos.chmod(p,0o700)\nprint(json.dumps({'stage':p}))"
        code, output, unused = ssh.execute(client, validator.remote_command(create), timeout=15)
        require(code == 0, 'Could not create a unique private deployment stage')
        stage = json.loads(output)['stage']
        require(re.fullmatch(r'/root/vps-console-deploy-[A-Za-z0-9_-]+', stage), 'Unexpected remote stage')
        result['remote_stage'] = stage
        archive = Path(reviewed['archive']).read_bytes()
        require(sha(archive) == reviewed['archive_sha256'] and sha(REMOTE_HELPER.read_bytes()) == reviewed['helper_sha256'],
                'Reviewed input changed before upload')
        with client.open_sftp() as sftp:
            for name, payload in (('release.tar.gz', archive), ('release-manifest.json', reviewed['manifest']),
                                  ('deploy_remote.py', reviewed['helper'])):
                with sftp.open(stage + '/' + name, 'wx') as stream:
                    stream.write(payload)
                sftp.chmod(stage + '/' + name, 0o600)
        configuration = {key: reviewed[key] for key in ('format', 'deployment_ip', 'release_files',
                        'release_sha256', 'archive_sha256', 'baseline_sha256', 'manifest_sha256', 'helper_sha256')}
        configuration['credentials'] = credentials(login_files)
        configuration['allow_registry_preflight'] = registry_preflight
        command = ('/usr/bin/python3 -B ' + shlex.quote(stage + '/deploy_remote.py') + ' --stage ' + shlex.quote(stage))
        stdin, stdout, stderr = client.exec_command(command, timeout=240)
        stdin.write(json.dumps(configuration))
        stdin.flush()
        stdin.channel.shutdown_write()
        configuration['credentials'].clear()
        # The remote helper prints sanitized metadata only. Never print raw
        # stderr or credential/configuration payloads on exceptions.
        output = stdout.read().decode('utf-8', 'replace')
        unused_error = stderr.read()
        code = stdout.channel.recv_exit_status()
        require(output.strip(), 'Remote transaction ended without a report; review retained stage')
        verification = json.loads(output.strip().splitlines()[-1])
        result.update(verification=verification, remote_exit_code=code,
                      success=code == 0 and verification.get('success') is True,
                      production_updated=verification.get('production_updated') is True)
    except Exception as error:
        result.update(error_type=type(error).__name__, failure='Deployment did not complete; inspect retained checkpoint and report')
    finally:
        client.close()
        with report_path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-directory', required=True, help='Absolute frozen candidate path')
    parser.add_argument('--validation-report', required=True, help='Exact successful actual Python 3.6 validation report')
    parser.add_argument('--baseline-release-directory', help='Previous deployed frozen console; default is original HY2 + AUTO baseline')
    parser.add_argument('--login-file', action='append', help='Local private login file; defaults to three adopted accounts')
    parser.add_argument('--report-name', default='console-optimization-deployment-20261013-01.json')
    parser.add_argument('--run', action='store_true', help='Explicitly deploy the reviewed source transaction on .63')
    parser.add_argument('--registry-preflight', action='store_true',
                        help='Use root state/config checks for members without locally saved login credentials; verify unchanged after stopping worker')
    args = parser.parse_args()
    require(re.fullmatch(r'console-optimization-deployment-[A-Za-z0-9_-]+\.json', args.report_name), 'Unexpected report filename')
    checked = review(args.release_directory, args.validation_report, args.baseline_release_directory)
    if not args.run:
        print(json.dumps({'local_review_passed': True, 'archive_sha256': checked['archive_sha256'],
                          'baseline': checked['baseline_label'], 'application_files': len(checked['release_files']),
                          'helper_sha256': checked['helper_sha256'], 'remote_connected': False,
                          'production_updated': False, 'explicit_run_required': True}, indent=2))
        return 0
    login_paths = args.login_file or [str(FOLDER / name) for name in DEFAULT_LOGIN_FILES]
    result = run(checked, login_paths, FOLDER / args.report_name, args.registry_preflight)
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, SyntaxError) as error:
        print('Local deployment review stopped: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
