"""Verify the complete 158 smart profile without changing the active exit.

The official client is isolated from FlClash and uses physical WLAN. Only
public provider data can be reused from the 63 cache; private custom rules,
client profiles, tokens, controller databases and GeoDB are never reused.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import traceback
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

import yaml
import smart_access as live


def cache_public_providers(profile, folder):
    source_cache = live.FOLDER.parent / 'raksmart-198.200.49.63' / 'smart-routing-validation' / 'core-check'
    specification = json.loads((live.FOLDER.parents[1] / 'panel' / 'smart-routing.json').read_text(encoding='utf-8'))
    copied = 0
    for name, public in specification['providers'].items():
        if public['type'] != 'http':
            continue
        provider = profile['rule-providers'].get(name)
        live.require(provider and provider['url'] == public['url'] and provider['path'] == public['path'],
                     'A public provider differs from the reviewed smart preset')
        relative = Path(public['path'])
        live.require(not relative.is_absolute() and '..' not in relative.parts,
                     'A provider cache path is invalid')
        source = source_cache / relative
        live.require(source.is_file() and not source.is_symlink(), 'Reviewed public provider cache is unavailable')
        destination = folder / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(str(source), str(destination))
        copied += 1
    live.require(copied == 23, 'Expected all 23 reviewed public HTTP provider caches')
    return copied


def session_login():
    login = json.loads((live.FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
    status, headers, body = live.request('POST', 'api/login',
                                       {'username': login['username'], 'password': login['password']})
    live.require(status == 200, '158 console login failed')
    live.cookie = headers['Set-Cookie'].split(';', 1)[0]
    return json.loads(body)['csrf']


def state_signature(state):
    return {'active_target': state.get('active_target'), 'active': state.get('active'),
            'exits': state.get('exits'), 'domains': state.get('domains'),
            'direct_domains': state.get('direct_domains'), 'routing_mode': state.get('routing_mode')}


def main():
    report = {'checked_at': datetime.now(timezone.utc).isoformat(), 'success': False, 'samples': []}
    process = None
    csrf = None
    folder = live.FOLDER / 'smart-routing-validation' / ('live-' + secrets.token_hex(5))
    folder.mkdir(parents=True)
    with (live.FOLDER / 'smart-mihomo-client.private.log').open('w', encoding='utf-8') as log:
        try:
            profile = yaml.safe_load((live.FOLDER / 'clash-smart-routing.private.yaml').read_text(encoding='utf-8'))
            before_profile = yaml.safe_load((live.FOLDER / 'smart-routing-before.private.yaml').read_text(encoding='utf-8'))
            before_state = json.loads((live.FOLDER / 'smart-routing-before-state.private.json').read_text(encoding='utf-8'))
            live.require(profile['proxies'] == before_profile['proxies'], 'Existing AUTO or fixed node identities changed')
            group = next(item for item in profile['proxy-groups'] if item['name'] == 'STATIC-SELECT')
            live.require(group['proxies'][0] == live.AUTO_NAME, 'AUTO is not the default selected entry')
            live.require(len(profile['rule-providers']) >= 27, 'Complete smart profile has missing providers')
            csrf = session_login()
            status, _, body = live.request('GET', 'api/state')
            state = json.loads(body)
            live.require(status == 200 and state['server_ip'] == live.IP and state['routing_mode'] == 'smart',
                         '158 live state is not using smart routing')
            live.require(state['active_target'] == before_state['active_target'] and
                         state.get('active') == before_state.get('active') and state['exits'] == before_state['exits'],
                         '158 active exit or account list changed during activation')
            expected = live.IP if state['active_target'] == 'server' else (
                (state.get('active') or {}).get('observed_ip') or (state.get('active') or {}).get('expected_ip'))
            live.require(bool(expected), 'No verified active exit IP')
            report['public_provider_caches_reused'] = cache_public_providers(profile, folder)
            proxy_port, control_port = live.free_port(), live.free_port()
            while control_port == proxy_port:
                control_port = live.free_port()
            secret = secrets.token_urlsafe(24)
            profile.update({'mixed-port': proxy_port, 'port': 0, 'socks-port': 0,
                            'allow-lan': False, 'bind-address': '127.0.0.1', 'interface-name': 'WLAN',
                            'external-controller': '127.0.0.1:' + str(control_port), 'secret': secret,
                            'tun': {'enable': False}, 'log-level': 'info', 'mode': 'rule',
                            'profile': {'store-selected': False, 'store-fake-ip': False}})
            candidate = folder / 'smart-client.private.yaml'
            candidate.write_text(yaml.safe_dump(profile, allow_unicode=True, sort_keys=False), encoding='utf-8')
            syntax = subprocess.run([str(live.BINARY), '-t', '-d', str(folder), '-f', str(candidate)],
                                    stdout=log, stderr=subprocess.STDOUT, timeout=60, creationflags=live.NO_WINDOW)
            live.require(syntax.returncode == 0, 'Official Mihomo rejected the full live smart profile')
            process = subprocess.Popen([str(live.BINARY), '-d', str(folder), '-f', str(candidate)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       creationflags=live.NO_WINDOW)
            opener = build_opener(ProxyHandler({}))
            controller = 'http://127.0.0.1:' + str(control_port)

            def api(path, method='GET'):
                query = Request(controller + path, method=method,
                                headers={'Authorization': 'Bearer ' + secret})
                with opener.open(query, timeout=4) as response:
                    body = response.read()
                    return json.loads(body) if body else None

            deadline = time.monotonic() + 100
            while True:
                live.require(process.poll() is None, 'Isolated smart client exited')
                try:
                    loaded = api('/providers/rules')['providers']
                    if len(loaded) == len(profile['rule-providers']) and all(
                            entry.get('ruleCount', 0) > 0 for entry in loaded.values()):
                        break
                except OSError:
                    pass
                live.require(time.monotonic() < deadline, 'Live smart rule providers did not load')
                time.sleep(.4)
            for direction in ['Direct', 'Proxy']:
                api('/providers/rules/' + quote('Custom ' + direction, safe=''), 'PUT')
            # Real HTTPS connections use the complete DNS and routing preset.
            # A website HTTP denial still establishes its selected network path.
            urls = [('api.bilibili.com', 'https://api.bilibili.com/x/web-interface/nav', 'DIRECT'),
                    ('static.hdslb.com', 'https://static.hdslb.com/', 'DIRECT'),
                    ('api.ipify.org', 'https://api.ipify.org', 'STATIC-SELECT')]
            for host, url, route in urls:
                for attempt in range(3):
                    response = subprocess.run([live.CURL, '--proxy', 'socks5h://127.0.0.1:' + str(proxy_port),
                                               '--noproxy', '', '--connect-timeout', '8', '--max-time', '25',
                                               '--silent', '--show-error', url], stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, timeout=30, creationflags=live.NO_WINDOW)
                    log.write('Live sample ' + host + ' attempt ' + str(attempt + 1) + ': ' + str(response.returncode) + '\n')
                    log.write(response.stderr.decode('utf-8', errors='replace'))
                    log.flush()
                    if response.returncode == 0:
                        break
                live.require(response.returncode == 0, 'A live sample could not establish its routed HTTPS connection')
                if host == 'api.ipify.org':
                    observed = response.stdout.decode('ascii').strip()
                    live.require(observed == expected, 'Smart AUTO IP does not match the current web exit')
                    report['auto_egress'] = {'observed_ip': observed, 'expected_ip': expected}
                time.sleep(.2)
                log.flush()
                lines = (live.FOLDER / 'smart-mihomo-client.private.log').read_text(encoding='utf-8', errors='replace').splitlines()
                matches = [line for line in lines if '--> ' + host + ':443' in line and ' using ' in line]
                live.require(any(('using DIRECT' in line if route == 'DIRECT' else 'using STATIC-SELECT' in line)
                                 for line in matches), 'The complete live profile chose an unexpected route')
                report['samples'].append({'domain': host, 'route': route, 'https_connection_succeeded': True})
            loaded = api('/providers/rules')['providers']
            live.require(all(loaded[name]['ruleCount'] > 0 for name in ['Custom Direct', 'Custom Proxy']),
                         'Live custom rule refresh emptied a provider')
            status, _, body = live.request('GET', 'api/state')
            final_state = json.loads(body)
            live.require(status == 200 and state_signature(final_state) == state_signature(state),
                         'The active target or routing settings changed during verification')
            status, _, body = live.request('GET', 'api/profile')
            live.require(status == 200 and yaml.safe_load(body)['proxies'] == before_profile['proxies'],
                         'Repeated profile read changed existing node identities')
            report.update(success=True, complete_profile_validated=True, all_providers_loaded=True,
                          custom_provider_refresh_succeeded=True, provider_count=len(loaded),
                          active_target=state['active_target'], auto_identity_preserved=True,
                          exit_accounts_preserved=True, active_target_preserved=True)
        except Exception:
            traceback.print_exc(file=log)
            report['error'] = 'Smart client verification failed; inspect the private diagnostic log.'
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if csrf:
                try:
                    live.request('POST', 'api/logout', {}, headers={'X-CSRF-Token': csrf})
                except Exception:
                    traceback.print_exc(file=log)
            live.cookie = None
    (live.FOLDER / 'smart-mihomo-client-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
