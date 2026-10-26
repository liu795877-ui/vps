"""Execute reviewed, account-scoped HY2 BBR trials through private SSH."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import stat

from ssh_access import FOLDER, connect, execute


REMOTE_TOOLS = '/root/vps-latency-tools-20261010'
HELPER_NAME = 'tune_hy2_profile_remote.py'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', choices=('snapshot', 'set', 'restore'), required=True)
    parser.add_argument('--port', type=int, choices=(443, 1443, 2443), default=443)
    parser.add_argument('--profile', choices=('standard', 'conservative', 'aggressive'), default='standard')
    parser.add_argument('--backup-dir', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    if not args.backup_dir.startswith('/root/vps-hy2-bbr-20261010-') or '/' in args.backup_dir[6:]:
        raise RuntimeError('Unexpected private profile checkpoint directory')
    report_path = Path(args.report).resolve()
    if report_path.parent != FOLDER.resolve() or report_path.suffix != '.json':
        raise RuntimeError('Reports must be JSON files in this deployment directory')
    sources = {name: (FOLDER / name).read_bytes() for name in
               (HELPER_NAME, 'optimize_udp_buffers_remote.py')}
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
            raise RuntimeError('Remote tools directory ownership differs')
        sftp.chmod(REMOTE_TOOLS, 0o700)
        for name, data in sources.items():
            destination = REMOTE_TOOLS + '/' + name
            try:
                info = sftp.lstat(destination)
            except FileNotFoundError:
                info = None
            if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_uid != 0):
                raise RuntimeError('Unsafe remote helper destination')
            with sftp.open(destination, 'wb') as stream:
                stream.write(data)
            sftp.chmod(destination, 0o600)
            with sftp.open(destination, 'rb') as stream:
                if hashlib.sha256(stream.read()).digest() != hashlib.sha256(data).digest():
                    raise RuntimeError('Uploaded tool differs from the reviewed source')
        argv = ['python3', REMOTE_TOOLS + '/' + HELPER_NAME,
                '--action', args.action, '--port', str(args.port),
                '--profile', args.profile, '--backup-dir', args.backup_dir,
                '--package-root', '/opt/vps-panel']
        code, output, _ = execute(client, ' '.join(shlex.quote(arg) for arg in argv), timeout=120)
        try:
            result = json.loads(output)
        except ValueError:
            raise RuntimeError('Profile helper did not return a sanitized report') from None
        if not isinstance(result, dict):
            raise RuntimeError('Unexpected profile report structure')
        result['helper_sha256'] = hashlib.sha256(sources[HELPER_NAME]).hexdigest()
        result['remote_exit_code'] = code
        report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(json.dumps({'action': args.action, 'port': args.port, 'profile': args.profile,
                          'success': result.get('success'), 'remote_exit_code': code,
                          'report': str(report_path)}, ensure_ascii=False))
        if code:
            raise SystemExit(code)
    finally:
        if sftp is not None:
            sftp.close()
        client.close()


if __name__ == '__main__':
    main()
