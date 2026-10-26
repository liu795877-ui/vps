"""Explicit real backup/export/preview acceptance; no restore or logout calls.

Creates one retained server-master-key encrypted backup. Portable passphrase,
download and decrypted snapshot live only in process memory. Running this
script uses the physical WLAN and must follow the parent's speed-test window.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import ssl
import sys

from ssh_access import FOLDER, connect
import frontend_motion_access as live


ROOT = FOLDER.parents[1]
NAME = 'HY2 多人整合部署备份'
REPORT = FOLDER / 'hy2-backup-verification.json'
CERTIFICATE_PIN = '719524027ace548d1251736cb2a2f603572d380e2237f8bdf8d3a3913af2b597'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def ssh_inventory(client):
    with client.open_sftp() as sftp:
        raw_registry = sftp.open('/var/lib/vps-panel/users.private.json').read()
        users = json.loads(raw_registry)['users']
        paths = {'admin/users.json': '/var/lib/vps-panel/users.private.json',
                 'admin/auth.json': '/var/lib/vps-panel/auth.private.json',
                 'admin/state.json': '/var/lib/vps-panel/state.private.json',
                 'admin/config.json': '/usr/local/etc/xray/config.json',
                 'system/base.private.yaml': '/var/lib/vps-panel/base.private.yaml',
                 'system/hy2.private.json': '/var/lib/vps-panel/hy2.private.json',
                 'system/hy2-server.crt.pem': '/var/lib/vps-panel/hy2-server.crt.pem',
                 'system/hy2-server.key.pem': '/var/lib/vps-panel/hy2-server.key.pem'}
        for user in users:
            identity = user['id']
            require(len(identity) == 16 and all(char in '0123456789abcdef' for char in identity),
                    'Unexpected member identity')
            paths['members/' + identity + '/state.json'] = '/var/lib/vps-panel/users/' + identity + '/state.private.json'
            paths['members/' + identity + '/config.json'] = '/usr/local/etc/xray-members/' + identity + '/config.json'
        digests = {}
        for name, path in paths.items():
            with sftp.open(path, 'rb') as stream:
                digests[name] = hashlib.sha256(stream.read()).hexdigest()
        return {'account_count': len(users) + 1, 'digests': digests}


def execute_verification():
    result = {'success': False, 'phase': 'login', 'deployment_ip': live.IP,
              'backup_name': NAME, 'restore_executed': False, 'logout_executed': False,
              'plaintext_archive_written': False}
    client = None
    try:
        login = json.loads((FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
        require(login.get('url') == live.ORIGIN + '/node-console/', 'Wrong administrator deployment')
        status, headers, body = live.request('POST', 'api/login',
            {'username': login['username'], 'password': login['password']})
        require(status == 200, 'Administrator login failed')
        authenticated = json.loads(body)
        require(authenticated.get('user', {}).get('id') == 'admin', 'Administrator session is required')
        session_headers = {'Cookie': headers['Set-Cookie'].split(';', 1)[0],
                           'X-CSRF-Token': authenticated['csrf']}
        # This process owns the session and lets it expire naturally. Never
        # calls logout or restoration, so existing user sessions stay intact.
        del login
        def api(method, path, value=None):
            response_status, unused_headers, response_body = live.request(method, path, value, session_headers)
            require(response_status == 200, 'Backup API acceptance failed at ' + path
                    + ' (HTTP ' + str(response_status) + ')')
            return json.loads(response_body)
        client = connect()
        before = ssh_inventory(client)
        require(before['account_count'] == 3, 'Three production accounts were expected')
        result['phase'] = 'create'
        # Reuse a retained backup after an interrupted verification only when
        # its exact name is already present; avoid silent duplicate snapshots.
        listing = api('GET', 'api/backups')
        matches = [item for item in listing['backups'] if item.get('name') == NAME]
        if matches:
            created = matches[0]
            result['existing_named_backup_reused'] = True
        else:
            created = api('POST', 'api/backups/create', {'name': NAME})
            result['existing_named_backup_reused'] = False
        require(created.get('portable') is False and created.get('scope') == 'system',
                'Retained backup must use the system master key')
        result.update(backup_id=created['id'], encrypted_server_backup_retained=True)
        result['phase'] = 'export-download'
        passphrase = secrets.token_urlsafe(40)
        exported = api('POST', 'api/backups/export', {'id': created['id'], 'password': passphrase})
        status, download_headers, encrypted = live.request('GET',
            'api/backups/download?token=' + exported['download_token'], headers=session_headers)
        require(status == 200 and len(encrypted) > 1000, 'Encrypted portable download failed')
        envelope = json.loads(encrypted)
        require(envelope.get('format') == 'node-console-backup' and envelope.get('cipher') == 'AES-256-GCM'
                and envelope.get('kdf') == 'PBKDF2-SHA256', 'Portable archive encryption differs')
        result.update(portable_encrypted_download=True, portable_archive_bytes=len(encrypted),
                      server_encryption='AES-256-GCM / server-key',
                      portable_encryption='AES-256-GCM / PBKDF2-SHA256',
                      portable_kdf_iterations=envelope.get('iterations'))
        result['phase'] = 'preview'
        preview = api('POST', 'api/backups/preview',
            {'data': base64.b64encode(encrypted).decode('ascii'), 'password': passphrase})
        require(preview.get('changes', {}).get('users') == 3 and len(preview.get('users', [])) == 3
                and any('HY2' in warning for warning in preview.get('warnings', [])),
                'Production backup preview omitted HY2 accounts')
        result.update(preview_valid=True, preview_account_count=3,
                      preview_includes_hy2=True, preview_restore_confirmed=False)
        result['phase'] = 'identity-check'
        sys.path.insert(0, str(ROOT))
        from panel import backups, hy2
        snapshot = json.loads(backups.decrypt(encrypted, password=passphrase, require_portable=True))
        files = snapshot['files']
        require(backups.HY2_FILES <= set(files), 'Backup omitted HY2 registry/certificate/key')
        require(snapshot.get('public_ip') == live.IP and snapshot.get('origin') == live.ORIGIN
                and snapshot.get('base_path') == '/node-console/', 'Backup belongs to another host')
        for name, digest in before['digests'].items():
            item = files.get(name)
            require(item and item.get('sha256') == digest
                    and hashlib.sha256(base64.b64decode(item['data'], validate=True)).hexdigest() == digest,
                    'Backup identity/source snapshot differs from production')
        registry = json.loads(base64.b64decode(files['system/hy2.private.json']['data']))
        hy2.validate_registry(registry)
        require(registry['enabled'] and len(registry['accounts']) == 3
                and registry['certificate_sha256'] == CERTIFICATE_PIN, 'Backed-up HY2 identities differ')
        certificate = base64.b64decode(files['system/hy2-server.crt.pem']['data']).decode('ascii')
        require(hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest() == CERTIFICATE_PIN,
                'Backed-up certificate pin changed')
        after = ssh_inventory(client)
        require(after == before, 'Backup acceptance changed account identity/state')
        listing = api('GET', 'api/backups')
        require(any(item['id'] == created['id'] and item['name'] == NAME for item in listing['backups']),
                'Retained encrypted backup is absent from the webpage')
        result.update(success=True, phase='complete', complete_account_count=3,
            hy2_extra_count=3, hy2_account_count=3, source_snapshot_verified=True,
            certificate_pin_preserved=True, private_registry_preserved=True,
            account_state_preserved=True, webpage_backup_visible=True,
            verified_at=datetime.now(timezone.utc).isoformat())
        del passphrase, encrypted, snapshot, files, registry, certificate
    except Exception as error:
        result.update(success=False, error_type=type(error).__name__)
        if type(error) is RuntimeError:
            result['check_failure'] = str(error)
        # Error text/body/configuration never enters the public report.
    finally:
        if client is not None:
            client.close()
        REPORT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-after-speed-tests', action='store_true', required=True)
    parser.parse_args()
    sys.stdout.reconfigure(encoding='utf-8')
    outcome = execute_verification()
    if not outcome['success']:
        raise SystemExit(1)
