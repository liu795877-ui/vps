"""Refresh the current subscription and select AUTO with a private rollback copy."""
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time
from urllib.parse import urlsplit

import yaml
import benchmark_hy2_latency as base
import frontend_motion_access as live
import verify_hy2_clients as helpers


FOLDER = helpers.FOLDER
LOCAL = Path('C:/Users/LENOVO/AppData/Roaming/com.follow/clash')
EXE = Path('D:/FlClash/FlClash.exe')
AUTO = 'AUTO · 网页切换'
HEALTH = {'url': 'https://www.gstatic.com/generate_204', 'expected-status': '204',
          'interval': 30, 'timeout': 5000, 'lazy': False}


def prefs():
    outer = json.loads((LOCAL / 'shared_preferences.json').read_bytes())
    value = outer['flutter.config']
    config = json.loads(value) if isinstance(value, str) else value
    identity = config['currentProfileId']
    helpers.require(isinstance(identity, str) and re.fullmatch(r'[0-9]{10,20}', identity), 'Invalid active profile identity')
    profile = next(item for item in config['profiles'] if item['id'] == identity)
    return outer, config, profile


def powershell(script):
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, creationflags=live.NO_WINDOW)
    helpers.require(result.returncode == 0, 'Client lifecycle command did not complete')
    return result.stdout.decode('utf-8-sig').strip()


def launch():
    return powershell("Start-Process -FilePath 'D:/FlClash/FlClash.exe' -WorkingDirectory 'D:/FlClash' -WindowStyle Hidden -PassThru | Select-Object Id | ConvertTo-Json -Compress")


def atomic(path, data):
    helpers.require(not path.is_symlink() and path.resolve().is_relative_to(LOCAL.resolve()), 'Unsafe local profile destination')
    temporary = path.with_name(path.name + '.refresh-' + secrets.token_hex(4))
    with temporary.open('xb') as stream:
        stream.write(data)
    os.replace(temporary, path)


def main():
    result = {'success': False, 'server_configuration_changes': 0, 'profile_id_preserved': True,
              'only_flclash_ui_restarted': True, 'other_proxy_processes_modified': False}
    base.TEMP_ROOT = FOLDER / 'flclash-refresh-private'
    directory = base.TEMP_ROOT / secrets.token_hex(8)
    result['private_backup_acl'] = base.make_private(directory)
    stopped, saved, installed = False, [], False
    try:
        outer, config, profile = prefs()
        original_id = profile['id']
        address = urlsplit(profile['url'])
        helpers.require(address.scheme == 'https' and address.hostname == live.HOST and address.port == 8443
            and re.fullmatch(r'/node-console/subscription/[A-Za-z0-9_-]{43,128}\.yaml', address.path)
            and not address.query and not address.fragment and not address.username,
            'The active subscription is not the authorized console subscription')
        status, unused_headers, content = live.request('GET', address.path[len('/node-console/'):])
        helpers.require(status == 200 and len(content) < 2097152, 'Latest subscription download failed')
        parsed = yaml.safe_load(content)
        group = next(g for g in parsed['proxy-groups'] if g['name'] == AUTO)
        helpers.require(all(group.get(k) == value for k, value in HEALTH.items()), 'Latest AUTO repair has not reached the subscription')
        helpers.require(group['proxies'] == ['HY2 · 网页切换', 'REALITY · TCP兼容'], 'Invalid AUTO transport order')
        candidate = directory / 'latest-smart-hy2.private.yaml'
        candidate.write_bytes(content)
        with (directory / 'syntax.private.log').open('w', encoding='utf-8') as log:
            syntax = subprocess.run([str(helpers.BINARY), '-t', '-d', str(directory), '-f', str(candidate)],
                stdout=log, stderr=subprocess.STDOUT, timeout=25, creationflags=live.NO_WINDOW)
        helpers.require(syntax.returncode == 0, 'Downloaded full profile failed official core validation')
        processes = json.loads(powershell('Get-Process -Name FlClash | Select-Object Id,Path | ConvertTo-Json -Compress'))
        processes = processes if isinstance(processes, list) else [processes]
        helpers.require(len(processes) == 1 and Path(processes[0]['Path']).resolve() == EXE.resolve(),
                        'A single expected active FlClash application is required')
        pid = int(processes[0]['Id'])
        # Stop only the known UI process; its helper owns the core lifecycle.
        powershell('Stop-Process -Id ' + str(pid) + ' -Force')
        stopped = True
        outer, config, profile = prefs()
        helpers.require(profile['id'] == original_id and profile['url'] == address.geturl(), 'Active profile changed during preparation')
        destinations = [LOCAL / 'shared_preferences.json', LOCAL / 'profiles' / (original_id + '.yaml')]
        for index, path in enumerate(destinations):
            helpers.require(path.is_file() and not path.is_symlink(), 'Expected client file is unavailable')
            saved.append((path, path.read_bytes()))
            (directory / ('before-' + str(index) + '.private')).write_bytes(saved[-1][1])
        result['previous_selection'] = profile.get('selectedMap', {}).get('STATIC-SELECT')
        result['previous_auto_run'] = config['appSetting'].get('autoRun')
        profile.setdefault('selectedMap', {})['STATIC-SELECT'] = AUTO
        profile['lastUpdateDate'] = datetime.now().isoformat()
        config['appSetting']['autoRun'] = True
        # This does not enable launch at Windows login; only starting the app
        # starts its proxy, matching the active proxy state before maintenance.
        outer['flutter.config'] = json.dumps(config, ensure_ascii=False) if isinstance(outer['flutter.config'], str) else config
        installed = True
        atomic(destinations[1], content)
        atomic(destinations[0], json.dumps(outer, ensure_ascii=False).encode('utf-8'))
        launch()
        deadline = time.monotonic() + 55
        while time.monotonic() < deadline:
            try:
                runtime = yaml.safe_load((LOCAL / 'config.yaml').read_text(encoding='utf-8-sig'))
                running_group = next(g for g in runtime['proxy-groups'] if g['name'] == AUTO)
                current_outer, current, selected = prefs()
                ready = all(running_group.get(k) == v for k, v in HEALTH.items())
                if ready and selected['id'] == original_id and selected.get('selectedMap', {}).get('STATIC-SELECT') == AUTO:
                    probe = subprocess.run([helpers.CURL, '--proxy', 'socks5h://127.0.0.1:7890', '--noproxy', '',
                        '--connect-timeout', '4', '--max-time', '8', '--ssl-no-revoke', '--silent', '--show-error',
                        'https://api.ipify.org'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=11, creationflags=live.NO_WINDOW)
                    if probe.returncode == 0 and probe.stdout.strip() == b'198.200.49.63':
                        result.update(success=True, profile_sha256=hashlib.sha256(content).hexdigest(),
                            profile_id=original_id, selected_group=AUTO, auto_run=True,
                            windows_auto_launch=current['appSetting'].get('autoLaunch'),
                            health_check=HEALTH, current_egress='198.200.49.63', runtime_policy_applied=True,
                            rollback_private_directory=str(directory), subscription_url_logged=False)
                        break
            except (OSError, ValueError, KeyError, TypeError, StopIteration,
                    yaml.YAMLError, subprocess.TimeoutExpired):
                pass
            time.sleep(1)
        helpers.require(result['success'], 'Refreshed active client did not become ready')
    except Exception as error:
        result['error_type'] = type(error).__name__
        if stopped:
            try:
                active = powershell('Get-Process -Name FlClash -ErrorAction SilentlyContinue | Select-Object Id,Path | ConvertTo-Json -Compress')
                if active:
                    records = json.loads(active)
                    records = records if isinstance(records, list) else [records]
                    for item in records:
                        if Path(item['Path']).resolve() == EXE.resolve():
                            powershell('Stop-Process -Id ' + str(int(item['Id'])) + ' -Force')
                if installed:
                    for path, data in saved:
                        atomic(path, data)
                # Maintenance began while the proxy was running. Preserve that
                # state on recovery too: the original autoRun=False would stop
                # the core when launching the restored application.
                recovery_outer, recovery_config, recovery_profile = prefs()
                recovery_config['appSetting']['autoRun'] = True
                recovery_outer['flutter.config'] = (json.dumps(recovery_config, ensure_ascii=False)
                    if isinstance(recovery_outer['flutter.config'], str) else recovery_config)
                atomic(LOCAL / 'shared_preferences.json',
                    json.dumps(recovery_outer, ensure_ascii=False).encode('utf-8'))
                launch()
                result['rollback_files_restored'] = installed
                result['rollback_application_relaunched'] = True
                result['rollback_auto_run_enabled_to_resume_proxy'] = True
                result['rollback_proxy_resumed'] = False
                recovery_deadline = time.monotonic() + 55
                while time.monotonic() < recovery_deadline:
                    try:
                        probe = subprocess.run([helpers.CURL, '--proxy', 'socks5h://127.0.0.1:7890',
                            '--noproxy', '', '--connect-timeout', '4', '--max-time', '8',
                            '--ssl-no-revoke', '--silent', '--show-error', 'https://api.ipify.org'],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=11,
                            creationflags=live.NO_WINDOW)
                        if probe.returncode == 0 and probe.stdout.strip() == b'198.200.49.63':
                            result['rollback_proxy_resumed'] = True
                            break
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                    time.sleep(1)
            except Exception:
                result['rollback_application_relaunched'] = False
        # Raw parsing errors can contain private configuration fragments.
        # The report retains the exception category without printing them.
    finally:
        (FOLDER / 'fast-regression-active-client-update.json').write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=True))
    return result


if __name__ == '__main__':
    raise SystemExit(0 if main()['success'] else 1)
