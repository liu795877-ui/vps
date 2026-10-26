"""Review or publish the frozen console adoption on .158.

Default is a local check. Only --run opens SSH, using this folder's pinned
ssh_access helper. Login secrets travel once on stdin and never enter files,
command arguments, logs, or reports.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex

import validate_console_optimization as validator

FOLDER = Path(__file__).resolve().parent
SERVER = '198.200.49.158'
ORIGIN = 'https://198-200-49-158.sslip.io:8443'
HELPER = FOLDER / 'deploy_console_optimization_remote.py'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def safe_file(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts
            and all(not part.is_symlink() for part in [path] + list(path.parents))
            and path.is_file() and path.parent.resolve() == FOLDER,
            'A regular input in the .158 folder is required')
    return path


def helper_assets(payload):
    tree = ast.parse(payload.decode('utf-8'), filename=str(HELPER), feature_version=(3, 6))
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('XRAY_TEMPLATE', 'HY2_TEMPLATE', 'PANEL_DROPIN'):
                values[name] = ast.literal_eval(node.value)
    require(set(values) == {'XRAY_TEMPLATE', 'HY2_TEMPLATE', 'PANEL_DROPIN'}
            and all(isinstance(value, str) for value in values.values()), 'Reviewed service assets are missing')
    return {
        '/etc/systemd/system/xray-panel@.service': sha(values['XRAY_TEMPLATE'].encode('utf-8')),
        '/etc/systemd/system/raksmart-hy2@.service': sha(values['HY2_TEMPLATE'].encode('utf-8')),
        '/etc/systemd/system/vps-panel.service.d/90-console-adoption.conf': sha(values['PANEL_DROPIN'].encode('utf-8')),
    }


def review(release_directory, validation_path, preflight_path):
    directory = Path(release_directory)
    require(directory.is_absolute() and '..' not in directory.parts
            and all(not path.is_symlink() for path in [directory] + list(directory.parents))
            and directory.is_dir() and directory.resolve().parent == FOLDER,
            'An absolute frozen release path in the .158 folder is required')
    checked = validator.local_review(directory.name)
    manifest_data = (directory / 'manifest.json').read_bytes()
    manifest = json.loads(manifest_data.decode('utf-8'))
    validation_data = safe_file(validation_path).read_bytes()
    validation = json.loads(validation_data.decode('utf-8'))
    verification = validation.get('verification', {})
    require(manifest.get('deployment_ip') == SERVER and manifest.get('origin') == ORIGIN,
            'The candidate belongs to another site')
    require(validation.get('success') is True and validation.get('release_tests_run') is True
            and verification.get('success') is True and verification.get('failures') == 0
            and verification.get('errors') == 0 and verification.get('tests_run', 0) >= 234
            and verification.get('python_version', [])[:2] == [3, 6]
            and verification.get('production_source_preserved') is True
            and verification.get('archive_sha256') == checked['archive_sha256']
            and verification.get('manifest_sha256') == checked['manifest_sha256']
            and verification.get('vendor_archive_sha256') == checked['vendor_archive_sha256'],
            'A passing actual Python 3.6 report for the exact source and dependency archives is required')
    preflight_data = safe_file(preflight_path).read_bytes()
    preflight = json.loads(preflight_data.decode('utf-8'))
    require(preflight.get('success') is True and preflight.get('server') == SERVER
            and preflight.get('origin') == ORIGIN and preflight.get('ssh_port') == 62970
            and preflight.get('production_updated') is False
            and preflight.get('source_sha256') == manifest.get('baseline_sha256')
            and preflight.get('source_file_count') == len(manifest['baseline_sha256'])
            and preflight.get('authenticated', {}).get('admin_login_passed') is True
            and preflight.get('authenticated', {}).get('exit_job_idle') is True
            and preflight.get('state', {}).get('managed_hash_matches') is True,
            'A matching successful .158 production preflight is required')
    require(set(preflight.get('binary_sha256', {})) == {
        '/usr/local/bin/xray', '/usr/local/bin/raksmart-hysteria2'}
        and all(re.fullmatch(r'[a-f0-9]{64}', value) for value in preflight['binary_sha256'].values()),
        'Reviewed proxy binary hashes are required')
    hy2 = preflight.get('legacy_hy2', {})
    require(hy2.get('password_compatible') is True and hy2.get('sni') == 'raksmart-hy2.local'
            and re.fullmatch(r'[a-f0-9]{64}', hy2.get('certificate_sha256', '')),
            'The existing HY2 authentication and TLS identity are required')
    require(not any(preflight.get('infrastructure_present', {}).values()), 'Expected first-adoption infrastructure is present')
    helper = safe_file(HELPER).read_bytes()
    assets = helper_assets(helper)
    return dict(checked, manifest=manifest_data, helper=helper, helper_sha256=sha(helper),
                format=manifest['format'], deployment_ip=SERVER, origin=ORIGIN,
                binary_sha256=preflight['binary_sha256'], certificate_sha256=hy2['certificate_sha256'],
                hy2_sni=hy2['sni'], migration_assets_sha256=assets,
                preflight_sha256=sha(preflight_data), validation_report_sha256=sha(validation_data),
                validation_report=str(validation_path), preflight_report=str(preflight_path))


def credentials(path):
    value = json.loads(safe_file(path).read_text(encoding='utf-8'))
    require(value.get('url') == ORIGIN + '/node-console/' and isinstance(value.get('username'), str)
            and isinstance(value.get('password'), str) and value['username'] and value['password'],
            'The administrator login belongs to another site or is malformed')
    return [{'username': value['username'], 'password': value['password']}]


def deploy(reviewed, login_path, report_path, rollback_stage=None):
    import ssh_access as ssh
    require(ssh.HOST == SERVER and ssh.PORT == 62970 and ssh.FOLDER.resolve() == FOLDER,
            'Unexpected SSH helper target')
    require(not report_path.exists() and not report_path.is_symlink(), 'Deployment report already exists')
    client = validator.strict_connect(ssh)
    result = {'success': False, 'started_at': datetime.now(timezone.utc).isoformat(),
              'server': SERVER, 'archive_sha256': reviewed['archive_sha256'],
              'manifest_sha256': reviewed['manifest_sha256'], 'vendor_archive_sha256': reviewed['vendor_archive_sha256'],
              'remote_helper_sha256': reviewed['helper_sha256'],
              'validation_report_sha256': reviewed['validation_report_sha256'],
              'preflight_sha256': reviewed['preflight_sha256'],
              'migration_assets_sha256': reviewed['migration_assets_sha256']}
    try:
        if rollback_stage:
            require(re.fullmatch(r'/root/vps-console-adoption-[A-Za-z0-9_-]+', rollback_stage),
                    'Unexpected rollback stage')
            stage = rollback_stage
            with client.open_sftp() as sftp:
                with sftp.open(stage + '/deploy_remote.py', 'r') as stream:
                    historical_helper = stream.read()
            require(sha(historical_helper) == reviewed['helper_sha256'],
                    'The retained rollback helper differs from reviewed code')
        else:
            create = ("import json,os,tempfile\np=tempfile.mkdtemp(prefix='vps-console-adoption-',dir='/root')\n"
                      "os.chmod(p,0o700)\nprint(json.dumps({'stage':p}))")
            code, output, unused = ssh.execute(client, validator.remote_command(create), timeout=15)
            require(code == 0, 'Could not create a unique private stage')
            stage = json.loads(output)['stage']
            require(re.fullmatch(r'/root/vps-console-adoption-[A-Za-z0-9_-]+', stage), 'Unexpected remote stage')
            archive = Path(reviewed['archive']).read_bytes()
            vendor_archive = Path(reviewed['vendor_archive']).read_bytes()
            require(sha(archive) == reviewed['archive_sha256']
                    and sha(vendor_archive) == reviewed['vendor_archive_sha256']
                    and sha(HELPER.read_bytes()) == reviewed['helper_sha256'],
                    'Reviewed source, dependencies or transaction changed before upload')
            with client.open_sftp() as sftp:
                for name, payload in (('release.tar.gz', archive), ('vendor.tar.gz', vendor_archive),
                                      ('release-manifest.json', reviewed['manifest']), ('deploy_remote.py', reviewed['helper'])):
                    with sftp.open(stage + '/' + name, 'wx') as stream:
                        stream.write(payload)
                    sftp.chmod(stage + '/' + name, 0o600)
        result['remote_stage'] = stage
        configuration = {key: reviewed[key] for key in (
            'format', 'deployment_ip', 'origin', 'release_files', 'release_sha256', 'archive_sha256',
            'baseline_sha256', 'manifest_sha256', 'helper_sha256', 'vendor_files', 'vendor_sha256',
            'vendor_archive_sha256', 'migration_assets_sha256', 'binary_sha256', 'certificate_sha256', 'hy2_sni')}
        configuration['credentials'] = credentials(login_path)
        command = ('/usr/bin/python3 -B ' + shlex.quote(stage + '/deploy_remote.py')
                   + ' --stage ' + shlex.quote(stage) + (' --rollback' if rollback_stage else ''))
        stdin, stdout, stderr = client.exec_command(command, timeout=300)
        stdin.write(json.dumps(configuration))
        stdin.flush()
        stdin.channel.shutdown_write()
        configuration['credentials'].clear()
        output = stdout.read().decode('utf-8', 'replace')
        unused = stderr.read()
        code = stdout.channel.recv_exit_status()
        require(output.strip(), 'Remote transaction ended without a report; retained stage requires review')
        remote = json.loads(output.strip().splitlines()[-1])
        result.update(verification=remote, remote_exit_code=code,
                      success=code == 0 and remote.get('success') is True,
                      production_updated=remote.get('production_updated') is True)
    except Exception as error:
        result.update(error_type=type(error).__name__, failure='Adoption did not complete; inspect retained stage and report')
    finally:
        client.close()
        with report_path.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-directory', required=True)
    parser.add_argument('--validation-report', required=True)
    parser.add_argument('--preflight-report', required=True)
    parser.add_argument('--login-file', default=str(FOLDER / 'panel-login.private.json'))
    parser.add_argument('--report-name', default='console-optimization-deployment-20261013-01.json')
    parser.add_argument('--rollback-stage')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    require(re.fullmatch(r'console-optimization-deployment-[A-Za-z0-9_-]+\.json', args.report_name),
            'Unexpected deployment report filename')
    checked = review(args.release_directory, args.validation_report, args.preflight_report)
    if not args.run:
        print(json.dumps({'local_review_passed': True, 'application_files': len(checked['release_files']),
                          'dependency_files': len(checked['vendor_files']), 'archive_sha256': checked['archive_sha256'],
                          'vendor_archive_sha256': checked['vendor_archive_sha256'],
                          'helper_sha256': checked['helper_sha256'],
                          'migration_assets_sha256': checked['migration_assets_sha256'],
                          'remote_connected': False, 'production_updated': False,
                          'explicit_run_required': True}, indent=2))
        return 0
    result = deploy(checked, args.login_file, FOLDER / args.report_name, args.rollback_stage)
    print(json.dumps({'success': result['success'], 'production_updated': result.get('production_updated', False),
                      'report': str(FOLDER / args.report_name), 'remote_stage': result.get('remote_stage'),
                      'phase': result.get('verification', {}).get('phase'),
                      'rollback_success': result.get('verification', {}).get('rollback_success')}, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
