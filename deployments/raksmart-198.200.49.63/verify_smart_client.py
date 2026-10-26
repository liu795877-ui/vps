"""Run the complete smart profile in an isolated official Mihomo client."""
from datetime import datetime, timezone
import json
import secrets
import shutil
import subprocess
import time
import traceback
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

import yaml
import verify_panel as live


def main():
    report = {'checked_at': datetime.now(timezone.utc).isoformat(), 'success': False, 'samples': []}
    process = None
    folder = live.FOLDER / 'smart-routing-validation' / ('live-' + secrets.token_hex(5))
    folder.mkdir(parents=True)
    with (live.FOLDER / 'smart-mihomo-client.private.log').open('w', encoding='utf-8') as log:
        try:
            profile = yaml.safe_load((live.FOLDER / 'clash-smart-routing.private.yaml').read_text(encoding='utf-8'))
            state = json.loads((live.FOLDER / 'smart-routing-before-state.private.json').read_text(encoding='utf-8'))
            expected = live.IP if state['active_target'] == 'server' else (
                (state.get('active') or {}).get('observed_ip') or (state.get('active') or {}).get('expected_ip'))
            live.require(bool(expected), 'No verified active exit IP')
            cache = live.FOLDER / 'smart-routing-validation' / 'core-check'
            for name, provider in profile['rule-providers'].items():
                if provider['type'] != 'http' or name.startswith('Custom '):
                    continue
                source = cache / provider['path']
                destination = folder / provider['path']
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_file():
                    shutil.copyfile(str(source), str(destination))
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
            # These are real HTTPS connections through the complete routing
            # profile. HTTP 403/412 still prove the selected network path.
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
            report.update(success=True, complete_profile_validated=True, all_providers_loaded=True,
                          custom_provider_refresh_succeeded=True, provider_count=len(loaded),
                          active_target=state['active_target'])
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
    (live.FOLDER / 'smart-mihomo-client-verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
