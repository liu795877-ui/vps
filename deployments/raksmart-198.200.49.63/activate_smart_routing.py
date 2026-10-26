"""Enable smart rules through the live API and verify stable subscriptions."""
from datetime import datetime, timezone
import json
import secrets
import traceback
from urllib.parse import urlsplit

import yaml
import verify_panel as live


def main():
    report = {'checked_at': datetime.now(timezone.utc).isoformat(), 'success': False}
    csrf = None
    restore = None
    with (live.FOLDER / 'smart-routing-activation.private.log').open('w', encoding='utf-8') as log:
        try:
            login = json.loads((live.FOLDER / 'panel-login.private.json').read_text(encoding='utf-8'))
            status, headers, body = live.request('POST', 'api/login',
                                                {'username': login['username'], 'password': login['password']})
            live.require(status == 200, 'Login failed')
            live.cookie = headers['Set-Cookie'].split(';', 1)[0]
            csrf = json.loads(body)['csrf']
            status, _, body = live.request('GET', 'api/state')
            before = json.loads(body)
            live.require(status == 200 and before['server_ip'] == live.IP and before['download_ready'],
                         'Unexpected initial node state')
            live.require((before.get('job') or {}).get('status') != 'running', 'An exit operation is still running')
            status, _, body = live.request('GET', 'api/profile')
            live.require(status == 200, 'Existing client profile is unavailable')
            original_profile = yaml.safe_load(body)
            (live.FOLDER / 'smart-routing-before.private.yaml').write_bytes(body)
            (live.FOLDER / 'smart-routing-before-state.private.json').write_text(json.dumps(before), encoding='utf-8')
            original_direct = before.get('direct_domains', [])
            original_proxy = before['domains']
            def save(direct, proxy):
                status, _, body = live.request('POST', 'api/routing', {
                    'mode': 'smart', 'direct_domains': direct, 'domains': proxy},
                    headers={'X-CSRF-Token': csrf})
                live.require(status == 200, 'Smart routing save failed')
            save(original_direct, original_proxy)
            status, _, body = live.request('GET', 'api/profile')
            live.require(status == 200, 'Smart profile download failed')
            profile = yaml.safe_load(body)
            providers = profile['rule-providers']
            custom = {direction: providers['Custom ' + direction.title()]
                      for direction in ['direct', 'proxy']}
            urls = {direction: provider['url'] for direction, provider in custom.items()}
            live.require(profile['proxies'][0]['uuid'] == original_profile['proxies'][0]['uuid'],
                         'AUTO identity changed')
            for direction, provider in custom.items():
                parsed = urlsplit(provider['url'])
                live.require(parsed.scheme == 'https' and parsed.hostname == live.HOST and parsed.port == 8443 and
                             parsed.path.startswith('/node-console/rules/custom/') and not parsed.query and
                             provider['interval'] == 300 and provider['proxy'] == 'DIRECT',
                             'Stable subscription metadata is invalid')
            def payload(direction, anonymous=True):
                saved_cookie = live.cookie
                if anonymous:
                    live.cookie = None
                try:
                    path = urlsplit(urls[direction]).path.removeprefix('/node-console/')
                    status, _, body = live.request('GET', path)
                    live.require(status == 200, 'Read-only rule subscription is unavailable')
                    return yaml.safe_load(body)['payload']
                finally:
                    live.cookie = saved_cookie
            for direction in custom:
                payload(direction)
            marker = secrets.token_hex(5)
            direct_test = 'direct-' + marker + '.invalid'
            proxy_test = 'proxy-' + marker + '.invalid'
            restore = (list(original_direct), list(original_proxy))
            save(original_direct + [direct_test], original_proxy + [proxy_test])
            live.require('DOMAIN-SUFFIX,' + direct_test in payload('direct') and
                         'DOMAIN-SUFFIX,' + proxy_test in payload('proxy'), 'Live subscription did not refresh')
            status, _, updated_profile = live.request('GET', 'api/profile')
            updated = yaml.safe_load(updated_profile)
            live.require(status == 200 and all(updated['rule-providers']['Custom ' + direction.title()]['url'] == urls[direction]
                                             for direction in custom) and
                         updated['proxies'][0]['uuid'] == original_profile['proxies'][0]['uuid'],
                         'Updating lists changed the stable client identity or subscription URLs')
            save(original_direct, original_proxy)
            restore = None
            live.require('DOMAIN-SUFFIX,' + direct_test not in payload('direct') and
                         'DOMAIN-SUFFIX,' + proxy_test not in payload('proxy'), 'Temporary subscription entries remain')
            status, _, body = live.request('GET', 'api/state')
            current = json.loads(body)
            live.require(status == 200 and current['routing_mode'] == 'smart' and current['routing_subscription']['enabled'] and
                         current['direct_domains'] == original_direct and current['domains'] == original_proxy and
                         current['active_target'] == before['active_target'] and current['exits'] == before['exits'] and
                         (current.get('active') or {}).get('id') == (before.get('active') or {}).get('id'),
                         'The active exit or account list changed during smart routing activation')
            status, _, body = live.request('GET', 'api/profile')
            live.require(status == 200, 'Final smart profile is unavailable')
            (live.FOLDER / 'clash-web-switch.private.yaml').write_bytes(body)
            (live.FOLDER / 'clash-smart-routing.private.yaml').write_bytes(body)
            report.update(success=True, routing_mode='smart', previous_mode=before['routing_mode'],
                          active_target=current['active_target'], static_exit_count=len(current['exits']),
                          auto_identity_preserved=True, exit_accounts_preserved=True,
                          read_only_subscriptions_verified=True, live_list_updates_verified=True,
                          temporary_domains_restored=True, interval_seconds=300)
        except Exception:
            traceback.print_exc(file=log)
            report['error'] = 'Activation failed; inspect the private diagnostic log.'
        finally:
            if restore:
                try:
                    status, _, _ = live.request('POST', 'api/routing', {
                        'mode': 'smart', 'direct_domains': restore[0], 'domains': restore[1]},
                        headers={'X-CSRF-Token': csrf})
                    live.require(status == 200, 'Temporary list restoration failed')
                    report['temporary_domains_restored'] = True
                except Exception:
                    traceback.print_exc(file=log)
                    report['temporary_domains_restored'] = False
            if csrf:
                try:
                    live.request('POST', 'api/logout', {}, headers={'X-CSRF-Token': csrf})
                except Exception:
                    traceback.print_exc(file=log)
            live.cookie = None
    (live.FOLDER / 'smart-routing-activation.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
