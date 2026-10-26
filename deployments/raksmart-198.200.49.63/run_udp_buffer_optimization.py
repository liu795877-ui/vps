"""Run the reviewed UDP-buffer helper over the existing private SSH transport.

The remote helper owns the private rollback checkpoint. Local reports contain
only the sanitized JSON returned by it; passwords and profile bodies stay out
of command arguments and output.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import stat

from ssh_access import FOLDER, connect, execute


HELPER = FOLDER / 'optimize_udp_buffers_remote.py'
REMOTE_TOOLS = '/root/vps-latency-tools-20261010'
REMOTE_HELPER = REMOTE_TOOLS + '/optimize_udp_buffers_remote.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', choices=('snapshot', 'apply', 'rollback'), required=True)
    parser.add_argument('--backup-dir', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    if not args.backup_dir.startswith('/root/vps-udp-buffer-optimization-20261010-'):
        raise RuntimeError('Unexpected remote checkpoint directory')
    if '/' in args.backup_dir.removeprefix('/root/'):
        raise RuntimeError('Checkpoint must be a direct child of /root')
    report_path = Path(args.report).resolve()
    if report_path.parent != FOLDER.resolve() or report_path.suffix != '.json':
        raise RuntimeError('Reports must be JSON files in this deployment directory')
    source = HELPER.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    client = connect()
    sftp = None
    try:
        sftp = client.open_sftp()
        try:
            info = sftp.lstat(REMOTE_TOOLS)
        except FileNotFoundError:
            sftp.mkdir(REMOTE_TOOLS, mode=0o700)
            info = sftp.lstat(REMOTE_TOOLS)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise RuntimeError('Remote helper directory must be owned by root')
        sftp.chmod(REMOTE_TOOLS, 0o700)
        try:
            info = sftp.lstat(REMOTE_HELPER)
        except FileNotFoundError:
            info = None
        if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_uid != 0):
            raise RuntimeError('Remote helper destination must be a root-owned regular file')
        with sftp.open(REMOTE_HELPER, 'wb') as stream:
            stream.write(source)
        sftp.chmod(REMOTE_HELPER, 0o600)
        with sftp.open(REMOTE_HELPER, 'rb') as stream:
            if hashlib.sha256(stream.read()).hexdigest() != digest:
                raise RuntimeError('Uploaded helper differs from reviewed local source')
        command = ' '.join(shlex.quote(item) for item in (
            'python3', REMOTE_HELPER, '--action', args.action,
            '--backup-dir', args.backup_dir, '--package-root', '/opt/vps-panel'))
        code, output, _ = execute(client, command, timeout=180)
        try:
            report = json.loads(output)
        except ValueError:
            raise RuntimeError('Remote helper did not return its sanitized JSON report') from None
        if not isinstance(report, dict):
            raise RuntimeError('Remote helper returned an unexpected report structure')
        report['reviewed_helper_sha256'] = digest
        report['remote_exit_code'] = code
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        print(json.dumps({'action': args.action, 'success': report.get('success'),
                          'phase': report.get('phase'), 'remote_exit_code': code,
                          'report': str(report_path)}, ensure_ascii=False))
        if code:
            raise SystemExit(code)
    finally:
        if sftp is not None:
            sftp.close()
        client.close()


if __name__ == '__main__':
    main()
