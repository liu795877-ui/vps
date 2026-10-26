"""Freeze locally, then explicitly publish the existing AUTO profile repair."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import stat

from ssh_access import FOLDER, connect, execute
from multiuser_update import compatible


ROOT = FOLDER.parents[1]
FILES = ('panel/accelerated_client.py', 'panel/test_accelerated_client.py')
HELPERS = ('publish_hy2_auto_health_remote.py', 'optimize_udp_buffers_remote.py')
RELEASE = FOLDER / 'hy2-auto-health-release'
MANIFEST = RELEASE / 'manifest.json'
FORMAT = 'vps-hy2-auto-health-v1'


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare():
    require(not RELEASE.exists(), 'Frozen AUTO repair release already exists')
    RELEASE.mkdir()
    for name in FILES:
        source = ROOT / name
        baseline = FOLDER / 'panel-release' / name
        require(source.is_file() and not source.is_symlink() and baseline.is_file(), 'Source baseline is unavailable')
        text = compatible(source.read_text(encoding='utf-8'), name)
        ast.parse(text, filename=name, feature_version=(3, 6))
        destination = RELEASE / 'release' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding='utf-8')
    for name in HELPERS:
        source = FOLDER / name
        ast.parse(source.read_text(encoding='utf-8'), filename=name, feature_version=(3, 6))
        (RELEASE / name).write_bytes(source.read_bytes())
    manifest = {'format': FORMAT, 'files': list(FILES), 'deployment_ip': '198.200.49.63',
        'prepared_at': datetime.now(timezone.utc).isoformat(), 'python_syntax': '3.6',
        'source_sha256': {name: sha(RELEASE / 'release' / name) for name in FILES},
        'baseline_sha256': {name: sha(FOLDER / 'panel-release' / name) for name in FILES},
        'helper_sha256': {name: sha(RELEASE / name) for name in HELPERS},
        'private_state_allowed_changes': ['profile', 'profile_version', 'profile_hash', 'profile_updated'],
        'transport_restarts': 0, 'only_panel_restarted': True, 'credential_rotation': False,
        'traffic_ledger_restored': False,
        'health_check': {'url':'https://www.gstatic.com/generate_204', 'expected-status':'204',
                         'interval':30, 'timeout':5000, 'lazy':False},
        'bbr_server_and_client': 'standard'}
    MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return manifest


def frozen():
    require(MANIFEST.is_file(), 'Prepare the concrete frozen release first')
    manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
    require(manifest.get('format') == FORMAT and manifest.get('files') == list(FILES), 'Unexpected release scope')
    for name in FILES:
        require(sha(RELEASE / 'release' / name) == manifest['source_sha256'][name], 'Frozen generator source changed')
    for name in HELPERS:
        require(sha(RELEASE / name) == manifest['helper_sha256'][name], 'Frozen maintenance helper changed')
    return manifest


def upload_directory(sftp, path):
    sftp.mkdir(path, mode=0o700)
    info = sftp.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0, 'Remote stage ownership differs')
    sftp.chmod(path, 0o700)


def publish(report_name):
    manifest = frozen()
    report = FOLDER / report_name
    require(report.parent.resolve() == FOLDER.resolve() and report.suffix == '.json' and not report.exists(),
            'Use a new JSON report filename in this deployment')
    stage = '/root/vps-hy2-auto-health-20261010-' + datetime.now(timezone.utc).strftime('%H%M%S') + '-' + secrets.token_hex(3)
    client = connect()
    try:
        with client.open_sftp() as sftp:
            for directory in (stage, stage + '/release', stage + '/release/panel'):
                upload_directory(sftp, directory)
            destinations = [('manifest.json', MANIFEST)]
            destinations += [(name, RELEASE / name) for name in HELPERS]
            destinations += [('release/' + name, RELEASE / 'release' / name) for name in FILES]
            for relative, source in destinations:
                destination = stage + '/' + relative
                with sftp.open(destination, 'wx') as stream:
                    stream.write(source.read_bytes())
                sftp.chmod(destination, 0o600)
                with sftp.open(destination, 'rb') as stream:
                    require(hashlib.sha256(stream.read()).hexdigest() == sha(source), 'Frozen upload checksum differs')
        argv = ['python3', stage + '/publish_hy2_auto_health_remote.py', '--stage', stage,
                '--package-root', '/opt/vps-panel']
        code, output, unused_error = execute(client, ' '.join(shlex.quote(value) for value in argv), timeout=120)
        try:
            result = json.loads(output)
        except ValueError:
            raise RuntimeError('Publisher did not return a sanitized report; inspect the private stage') from None
        result['remote_exit_code'] = code
        result['frozen_manifest_sha256'] = sha(MANIFEST)
        with report.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(result, indent=2) + '\n')
        require(result.get('success') and code == 0, 'Publication did not pass; review its sanitized report')
        # Advance the local deployed-source baseline only after host acceptance.
        for name in FILES:
            (FOLDER / 'panel-release' / name).write_bytes((RELEASE / 'release' / name).read_bytes())
        return {'success': True, 'stage': stage, 'report': str(report),
                'profiles_refreshed': result['profiles_refreshed'], 'transport_restarts': 0}
    finally:
        client.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('prepare', 'publish'), required=True)
    parser.add_argument('--report', default='hy2-auto-health-update.json')
    args = parser.parse_args()
    result = prepare() if args.action == 'prepare' else publish(args.report)
    print(json.dumps(result, ensure_ascii=True))
