"""Save the requested learning-site DIRECT override and verify a fresh client.

Only a query-free sample URL is sent to the panel. Course links and parameters
are never requested or saved. Installed FlClash and other users are untouched.
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
import frontend_motion_access as live
from ssh_access import connect, execute
from verify_panel import BINARY, CURL, free_port

DOMAIN = 'mooc1.chaoxing.com'
FOLDER = live.FOLDER
REPORT = FOLDER / 'routing-url-client-verification.json'


SNAPSHOT = r'''
import hashlib, json, re, subprocess
from pathlib import Path
root = Path('/var/lib/vps-panel')
registry = root / 'users.private.json'
members = json.loads(registry.read_text())['users']
if isinstance(members, dict):
    members = list(members.values())
members = [entry for entry in members if entry['role'] == 'member']
assert all(re.fullmatch(r'[0-9a-f]{16}', entry['id']) for entry in members)
paths = [registry, root / 'auth.private.json', Path('/usr/local/etc/xray/config.json'),
         Path('/usr/local/etc/raksmart-hy2/server.yaml')]
services = ['xray.service', 'raksmart-hy2.service', 'caddy.service']
for entry in members:
    directory = root / 'users' / entry['id']
    paths.extend(path for path in directory.rglob('*') if path.is_file())
    paths.extend(path for path in (Path('/usr/local/etc/xray-members') / entry['id']).rglob('*') if path.is_file())
    services.append('xray-panel@' + entry['id'] + '.service')
hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
processes = {}
for service in services:
    output = subprocess.check_output(['systemctl', 'show', service]).decode()
    fields = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    processes[service] = {key: fields[key] for key in ['ActiveState', 'MainPID', 'ExecMainStartTimestampMonotonic']}
    assert fields['ActiveState'] == 'active'
print(json.dumps({'hashes': hashes, 'processes': processes,
                  'admin_state': json.loads((root / 'state.private.json').read_text())}))
'''


def server_snapshot(client):
    code, output, _ = execute(client, "python3 - <<'ROUTING_URL_SNAPSHOT'\n" + SNAPSHOT + '\nROUTING_URL_SNAPSHOT\n', timeout=35)
    live.require(code == 0, 'Could not verify live account and proxy preservation')
    return json.loads(output)


def main():
    report = {'success': False, 'checked_at': datetime.now(timezone.utc).isoformat(),
              'deployment_ip': live.IP, 'domain': DOMAIN, 'saved_account': 'admin'}
    work = FOLDER / 'routing-url-client-validation' / secrets.token_hex(5)
    work.mkdir(parents=True)
    client = None
    process = None
    csrf = None
    try:
        client = connect()
        before = server_snapshot(client)
        (work / 'before.private.json').write_text(json.dumps(before), encoding='utf-8')
        login = json.loads((FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
        status, headers, body = live.request('POST', 'api/login',
                                            {'username': login['username'], 'password': login['password']})
        live.require(status == 200, 'Could not log into the administrator account')
        live.cookie = headers['Set-Cookie'].split(';', 1)[0]
        csrf = json.loads(body)['csrf']
        status, _, body = live.request('GET', 'api/state')
        live.require(status == 200, 'Could not read existing administrator rules')
        state = json.loads(body)
        live.require(state['user']['username'] == 'admin' and state['routing_mode'] == 'smart',
                     'Learning override requires the existing administrator smart profile')
        direct = list(state['direct_domains'])
        covered = any(DOMAIN == domain or DOMAIN.endswith('.' + domain) for domain in direct)
        if not covered:
            # Domain-only normalization is exercised without sending private course parameters.
            direct.append('https://' + DOMAIN + '/')
            status, _, _ = live.request('POST', 'api/routing',
                                        {'mode': 'smart', 'domains': state['domains'], 'direct_domains': direct},
                                        {'X-CSRF-Token': csrf})
            live.require(status == 200, 'The learning-site DIRECT rule could not be saved')
        status, _, body = live.request('GET', 'api/state')
        live.require(status == 200, 'Saved administrator rules could not be read')
        current = json.loads(body)
        live.require(any(DOMAIN == domain or DOMAIN.endswith('.' + domain)
                         for domain in current['direct_domains']), 'Learning domain is missing from DIRECT overrides')
        after = server_snapshot(client)
        live.require(before['hashes'] == after['hashes'], 'Another account or proxy configuration changed')
        live.require(before['processes'] == after['processes'], 'A proxy process restarted during the rule save')
        stable_fields = set(before['admin_state']) - {'direct_domains', 'applied_direct_domains', 'updated'}
        live.require(all(before['admin_state'][key] == after['admin_state'].get(key) for key in stable_fields),
                     'Unrelated administrator state changed during the rule save')
        report.update(rule_saved=True, new_rule_added=not covered,
                      exact_hostname_scope=DOMAIN in current['direct_domains'],
                      other_accounts_and_proxy_configs_preserved=True, proxy_processes_preserved=True,
                      client_reimport_required=False, subscription_refresh_seconds=300)
        status, _, payload = live.request('GET', 'api/profile')
        live.require(status == 200, 'The current client profile could not be downloaded')
        profile = yaml.safe_load(payload)
        (work / 'downloaded.private.yaml').write_bytes(payload)
        cache = FOLDER / 'smart-routing-validation/core-check'
        for name, provider in profile['rule-providers'].items():
            if provider.get('type') != 'http':
                continue
            relative = Path(provider['path'])
            live.require(not relative.is_absolute() and '..' not in relative.parts, 'Unexpected provider cache path')
            destination = work / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if name.startswith('Custom '):
                status, _, content = live.request('GET', provider['url'].split('/node-console/', 1)[1])
                live.require(status == 200, 'The saved custom subscription could not be fetched')
                destination.write_bytes(content)
                if name == 'Custom Direct':
                    expected = ('DOMAIN-SUFFIX,' + DOMAIN).encode()
                    if not covered:
                        live.require(expected in content, 'The learning domain was not exported into the live DIRECT provider')
                    live.require(b'https://' not in content and b'?' not in content, 'A website URL was stored as a rule')
                    report['domain_only_subscription_verified'] = True
            else:
                source = cache / relative
                live.require(source.is_file(), 'A maintained provider cache is missing')
                shutil.copyfile(str(source), str(destination))
        proxy_port, control_port = free_port(), free_port()
        while proxy_port == control_port:
            control_port = free_port()
        secret = secrets.token_urlsafe(24)
        profile.update({'mixed-port': proxy_port, 'port': 0, 'socks-port': 0,
                        'allow-lan': False, 'bind-address': '127.0.0.1', 'interface-name': 'WLAN',
                        'external-controller': '127.0.0.1:' + str(control_port), 'secret': secret,
                        'tun': {'enable': False}, 'log-level': 'info', 'mode': 'rule',
                        'profile': {'store-selected': False, 'store-fake-ip': False}})
        candidate = work / 'client.private.yaml'
        candidate.write_text(yaml.safe_dump(profile, allow_unicode=True, sort_keys=False), encoding='utf-8')
        log_path = work / 'client.private.log'
        with log_path.open('w', encoding='utf-8') as log:
            syntax = subprocess.run([str(BINARY), '-t', '-d', str(work), '-f', str(candidate)],
                                    stdout=log, stderr=subprocess.STDOUT, timeout=60, creationflags=live.NO_WINDOW)
            live.require(syntax.returncode == 0, 'The complete smart profile failed official Mihomo syntax validation')
            process = subprocess.Popen([str(BINARY), '-d', str(work), '-f', str(candidate)],
                                       stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                       creationflags=live.NO_WINDOW)
            opener = build_opener(ProxyHandler({}))
            def api(resource, method='GET'):
                query = Request('http://127.0.0.1:' + str(control_port) + resource, method=method,
                                headers={'Authorization': 'Bearer ' + secret})
                with opener.open(query, timeout=4) as response:
                    body = response.read()
                    return json.loads(body) if body else None
            deadline = time.monotonic() + 40
            while True:
                live.require(process.poll() is None, 'The isolated test client exited')
                try:
                    loaded = api('/providers/rules')['providers']
                    if all(loaded.get(name, {}).get('ruleCount', 0) for name in profile['rule-providers']):
                        break
                except OSError:
                    pass
                live.require(time.monotonic() < deadline, 'The full smart rule providers did not initialize')
                time.sleep(.25)
            api('/providers/rules/' + quote('Custom Direct', safe=''), 'PUT')
            response = subprocess.run([CURL, '--proxy', 'socks5h://127.0.0.1:' + str(proxy_port),
                                       '--noproxy', '', '--connect-timeout', '8', '--max-time', '20',
                                       '--silent', '--show-error', '--output', 'NUL', '--write-out', '%{http_code}',
                                       'https://' + DOMAIN + '/'], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, timeout=25, creationflags=live.NO_WINDOW)
            log.flush()
            time.sleep(.2)
            lines = log_path.read_text(encoding='utf-8', errors='replace').splitlines()
            routed = [line for line in lines if '--> ' + DOMAIN + ':443' in line and ' using ' in line]
            live.require(any('using DIRECT' in line and 'Custom Direct' in line for line in routed),
                         'The learning-site connection did not select the custom DIRECT rule')
            report.update(official_mihomo_full_profile_accepted=True, provider_count=len(loaded),
                          actual_route_verified='DIRECT', matched_provider='Custom Direct',
                          https_connection_succeeded=response.returncode == 0,
                          homepage_http_status=response.stdout.decode('ascii', errors='replace').strip(),
                          private_course_url_requested=False, installed_client_unchanged=True)
            live.require(response.returncode == 0, 'The learning-site homepage HTTPS connection failed')
            report['success'] = True
        print(json.dumps(report, ensure_ascii=False))
        return 0
    except Exception:
        (work / 'error.private.log').write_text(traceback.format_exc(), encoding='utf-8')
        print('Routing URL verification requires attention; inspect its private log.')
        return 1
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if csrf and live.cookie:
            try:
                live.request('POST', 'api/logout', {}, {'X-CSRF-Token': csrf})
            except OSError:
                pass
        live.cookie = None
        if client is not None:
            client.close()
        REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


if __name__ == '__main__':
    raise SystemExit(main())
