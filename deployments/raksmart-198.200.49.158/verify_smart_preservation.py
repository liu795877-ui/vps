"""Read-only SSH acceptance for an existing 158 node after smart activation."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import traceback

import yaml
from ssh_access import connect, execute, FOLDER


PROGRAM = r'''
import hashlib, json, subprocess
from pathlib import Path

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

before = Path(BEFORE)
baseline = json.loads((before / 'state.private.json').read_text())
current = json.loads(Path('/var/lib/vps-panel/state.private.json').read_text())
hash_file = before / 'protected-hashes.json'
protected = json.loads(hash_file.read_text()) if hash_file.is_file() else FALLBACK_HASHES
require(isinstance(protected, dict) and len(protected) >= 10, 'Protected configuration baseline is incomplete')
for path, expected in protected.items():
    candidate = Path(path)
    require(candidate.is_file() and not candidate.is_symlink(), 'A protected configuration file is unavailable')
    require(hashlib.sha256(candidate.read_bytes()).hexdigest() == expected,
            'A protected node, service, account or DNS configuration changed')
config = Path('/usr/local/etc/xray/config.json')
config_hash = hashlib.sha256(config.read_bytes()).hexdigest()
require(config_hash == baseline['managed_hash'] == current['managed_hash'],
        'Live Xray configuration no longer matches the original managed state')
identity_fields = ['base', 'public', 'short', 'auto_id', 'exits', 'applied_exits',
                   'active_id', 'managed_hash', 'updated', 'domains']
for field in identity_fields:
    require(current.get(field) == baseline.get(field), 'An existing node identity, exit or domain setting changed')
for field in ['direct_domains']:
    require(current.get(field, []) == baseline.get(field, []), 'An existing custom domain list changed')
if baseline.get('rule_token'):
    require(current.get('rule_token') == baseline['rule_token'], 'Existing rule subscription token changed')
require(current.get('routing_mode') == 'smart' and current.get('applied_routing_mode') == 'smart',
        'Smart routing has not been activated')
require(current.get('applied_domains') == current['domains'] and
        current.get('applied_direct_domains') == current.get('direct_domains', []),
        'Applied custom domain lists do not match the saved lists')
require(bool(current.get('rule_token')), 'Independent rule subscription token is missing')
require(len(current['history']) == len(baseline['history']), 'Existing exit history count changed')
for old, new in zip(baseline['history'], current['history']):
    require(all(new.get(key) == value for key, value in old.items()), 'Existing exit history content changed')
services = {}
for service in ['xray.service', 'raksmart-hy2.service', 'vps-panel.service', 'caddy.service']:
    statuses = {}
    for mode, expected in [('is-active', 'active'), ('is-enabled', 'enabled')]:
        result = subprocess.run(['systemctl', mode, service], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        actual = result.stdout.decode().strip()
        require(result.returncode == 0 and actual == expected, 'An installed service is not running and enabled')
        statuses[mode] = actual
    services[service] = statuses
config_data = json.loads(config.read_text())
require(config_data.get('dns') == baseline['base'].get('dns'), 'The existing Xray DNS fix changed')
active = next((item for item in current['applied_exits'] if item['id'] == current['active_id']), None)
print(json.dumps({'success': True, 'protected_configuration_count': len(protected),
                  'protected_hash_baseline': 'deployment-stop' if hash_file.is_file() else 'preflight',
                  'xray_configuration_unchanged': True, 'node_identities_preserved': True,
                  'all_exit_credentials_and_state_preserved': True, 'active_exit_preserved': True,
                  'existing_domain_lists_preserved': True, 'history_preserved': True,
                  'dns_preserved': True, 'auth_and_hy2_preserved': True,
                  'all_services_active_and_enabled': True, 'services': services,
                  'static_exit_count': len(current['exits']),
                  'active_target': 'static' if active else 'server',
                  'verified_active_ip': (active.get('observed_ip') or active.get('expected_ip')) if active else '198.200.49.158'}))
'''


def main():
    report = {'checked_at': datetime.now(timezone.utc).isoformat(), 'success': False}
    with (FOLDER / 'smart-routing-preservation.private.log').open('w', encoding='utf-8') as log:
        client = None
        try:
            updated = json.loads((FOLDER / 'smart-routing-update.json').read_text(encoding='utf-8'))
            require(updated.get('success'), 'Deployment has not completed')
            backup = updated['backup']
            require(backup.startswith('/root/raksmart-proxy-deploy-20261009/smart-routing-') and
                    backup.endswith('/before') and '..' not in Path(backup).parts,
                    'The deployment backup path is unexpected')
            preflight = json.loads((FOLDER / 'smart-routing-preflight.private.json').read_text(encoding='utf-8'))
            old_profile = yaml.safe_load((FOLDER / 'smart-routing-before.private.yaml').read_text(encoding='utf-8'))
            new_profile = yaml.safe_load((FOLDER / 'clash-smart-routing.private.yaml').read_text(encoding='utf-8'))
            require(old_profile['proxies'] == new_profile['proxies'], 'AUTO or fixed node identities changed')
            require(new_profile['proxies'][0]['server'] == '198.200.49.158', 'The smart profile belongs to another VPS')
            legacy = FOLDER / 'clash-unified-exits.private.yaml'
            if legacy.is_file():
                legacy_profile = yaml.safe_load(legacy.read_text(encoding='utf-8'))
                require(legacy_profile['proxies'][0]['uuid'] == new_profile['proxies'][0]['uuid'],
                        'The previously downloaded AUTO identity changed')
                report['legacy_auto_identity_preserved'] = True
                report['legacy_profile_sha256'] = hashlib.sha256(legacy.read_bytes()).hexdigest()
            client = connect()
            program = 'BEFORE = ' + repr(backup) + '\nFALLBACK_HASHES = ' + repr(preflight['protected_hashes']) + '\n' + PROGRAM
            command = "python3 - <<'SMART_PRESERVATION_CHECK'\n" + program + '\nSMART_PRESERVATION_CHECK\n'
            code, output, error = execute(client, command, timeout=45)
            log.write(output + '\n' + error)
            require(code == 0, 'Remote preservation check failed')
            remote = json.loads(output)
            require(remote.get('success'), 'Remote preservation check did not complete')
            report.update(remote)
            report['all_client_node_identities_preserved'] = True
            report['auto_identity_preserved'] = True
        except Exception:
            traceback.print_exc(file=log)
            report['error'] = 'Preservation verification failed; inspect the private diagnostic log.'
        finally:
            if client is not None:
                client.close()
    (FOLDER / 'smart-routing-preservation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


if __name__ == '__main__':
    raise SystemExit(main())
