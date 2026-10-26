"""Export current admin smart profile privately; preserve the live FlClash."""
import hashlib
import json
from pathlib import Path
import secrets
import subprocess

import yaml
import benchmark_hy2_latency as base
import verify_hy2_clients as helpers


def main():
    root = helpers.FOLDER / 'client-profile-private'
    helpers.require(not root.is_symlink(), 'Unsafe client export parent')
    base.TEMP_ROOT = root
    directory = root / secrets.token_hex(8)
    acl = base.make_private(directory)
    ssh, sftp = None, None
    try:
        ssh = helpers.connect()
        sftp = ssh.open_sftp()
        accounts, unused_store = helpers.collect_accounts(sftp)
        admin = next(account for account in accounts if account['id'] == 'admin')
        state = helpers.private_json(sftp, admin['state_path'])
        profile = state['profile']
        candidate = directory / '198.200.49.63-smart-hy2.private.yaml'
        candidate.write_text(profile, encoding='utf-8')
        parsed = yaml.safe_load(profile)
        assert any(node['type'] == 'hysteria2' for node in parsed['proxies'])
        assert any(group['type'] == 'fallback' for group in parsed['proxy-groups'])
        with (directory / 'syntax.private.log').open('w', encoding='utf-8') as log:
            syntax = subprocess.run([str(helpers.BINARY), '-t', '-d', str(directory), '-f', str(candidate)],
                stdout=log, stderr=subprocess.STDOUT, timeout=25, creationflags=base.live.NO_WINDOW)
        helpers.require(syntax.returncode == 0, 'Current full client profile syntax did not pass')
        local = Path('C:/Users/LENOVO/AppData/Roaming/com.follow/clash')
        prefs = json.loads((local / 'shared_preferences.json').read_bytes())['flutter.config']
        prefs = json.loads(prefs) if isinstance(prefs, str) else prefs
        active_id = prefs['currentProfileId']
        active_path = local / 'profiles' / (active_id + '.yaml')
        prior = yaml.safe_load(active_path.read_text(encoding='utf-8-sig'))
        old = next(node for node in prior['proxies'] if node.get('type') == 'vless'
                   and node.get('server') == '198.200.49.63' and node.get('port') == 443)
        matches = old.get('uuid') == admin['nodes']['xray'].get('uuid')
        helpers.require(matches, 'The active local TCP profile is not the current admin identity')
        result = {'success': True, 'full_profile_syntax_accepted': True, 'private_directory_acl': acl,
            'private_export': str(candidate), 'profile_sha256': hashlib.sha256(profile.encode()).hexdigest(),
            'profile_version': state.get('profile_version'), 'active_local_profile_id': active_id,
            'active_local_profile_has_hy2': any(node.get('type') == 'hysteria2' for node in prior['proxies']),
            'local_tcp_identity_matches_current_admin': matches, 'current_expected_exit': admin['expected_ip'],
            'live_client_modified': False, 'server_modified': False,
            'export_is_intentionally_retained_for_user_import': True}
        (helpers.FOLDER / 'fast-regression-client-prepared.json').write_text(
            json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(result))
    finally:
        if sftp is not None:
            sftp.close()
        if ssh is not None:
            ssh.close()


if __name__ == '__main__':
    main()
