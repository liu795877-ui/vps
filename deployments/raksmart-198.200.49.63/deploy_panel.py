"""Upload the locally reviewed release and install the independent 63 console."""
import hashlib
import json
from pathlib import Path
import shlex
from ssh_access import connect, execute, FOLDER

STAGE = '/root/raksmart-proxy-deploy-20261009/panel'


def main():
    manifest = json.loads((FOLDER / 'panel-release-manifest.json').read_text(encoding='utf-8'))
    archive = FOLDER / 'panel-release.private.tar.gz'
    expected = manifest['archive_sha256']
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise RuntimeError('Prepared archive has changed; restage it before installation')
    files = [('panel-release.private.tar.gz', 'release.tar.gz'),
             ('install_panel.py', 'install_panel.py'),
             ('panel-auth-seed.private.json', 'auth-seed.private.json'),
             ('panel-base.private.yaml', 'base.private.yaml'),
             ('panel-release-manifest.json', 'release-manifest.json'),
             ('Caddyfile', 'Caddyfile'), ('caddy.service', 'caddy.service')]
    for local, remote in files:
        if not (FOLDER / local).is_file():
            raise RuntimeError('Missing prepared input: ' + local)
    client = connect()
    try:
        code, output, error = execute(client, 'install -d -m 0700 ' + shlex.quote(STAGE))
        if code:
            raise RuntimeError('Could not create the private installation staging directory')
        with client.open_sftp() as sftp:
            for local, remote in files:
                sftp.put(str(FOLDER / local), STAGE + '/' + remote)
                sftp.chmod(STAGE + '/' + remote, 0o600)
        command = ('set -eu\ncd ' + shlex.quote(STAGE) + '\n'
                   "printf '%s  release.tar.gz\\n' " + shlex.quote(expected) + ' | sha256sum --check --status\n'
                   'tar -xzf release.tar.gz\npython3 install_panel.py\n')
        code, output, error = execute(client, command, timeout=240)
        (FOLDER / 'panel-deployment.private.log').write_text(output + '\n' + error, encoding='utf-8')
        with client.open_sftp() as sftp:
            for remote, local in [('install-state.json', 'panel-install-state.json'),
                                  ('install-events.jsonl', 'panel-install-events.jsonl')]:
                try:
                    sftp.get(STAGE + '/' + remote, str(FOLDER / local))
                except FileNotFoundError:
                    pass
        if code:
            raise RuntimeError('Console installation failed; inspect panel-install-state.json and private deployment log')
        result = json.loads(output.strip().splitlines()[-1])
        (FOLDER / 'panel-deployment-result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result))
    finally:
        client.close()


if __name__ == '__main__':
    main()
