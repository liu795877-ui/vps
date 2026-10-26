"""Verify authenticated user boundaries, subscriptions and owner preservation.

Member A's server route is reapplied through an isolated Manager, then its
complete private config/state bytes are restored. Only A is restarted. A
temporary .invalid rule is also restored. No admin configuration is changed.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
import traceback

import yaml
from ssh_access import FOLDER, connect, execute
import frontend_motion_access as live


class Session:
    def __init__(self, login):
        status, headers, body = live.request('POST', 'api/login',
            {'username': login['username'], 'password': login['password']})
        live.require(status == 200, 'A prepared account could not log in')
        payload = json.loads(body)
        self.cookie = headers['Set-Cookie'].split(';', 1)[0]
        self.csrf = payload['csrf']
        self.user = payload['user']

    def request(self, method, path, body=None):
        return live.request(method, path, body,
                            {'Cookie': self.cookie, 'X-CSRF-Token': self.csrf})

    def json(self, method, path, body=None, expected=200):
        status, _, response = self.request(method, path, body)
        live.require(status == expected, 'Unexpected status in account isolation verification')
        return json.loads(response)

    def profile(self):
        status, _, body = self.request('GET', 'api/profile')
        live.require(status == 200, 'An isolated profile could not be downloaded')
        return body.decode('utf-8')

    def logout(self):
        self.request('POST', 'api/logout', {})


PRESERVATION = r'''
import hashlib, json, os, re, subprocess
from pathlib import Path
backup = Path(BACKUP)
hashes = json.loads((backup / 'protected-hashes.json').read_text())
processes = json.loads((backup / 'protected-processes.json').read_text())
owner = Path('/var/lib/vps-panel/state.private.json')
assert owner.read_bytes() == (backup / 'state.private.json').read_bytes(), 'Administrator state changed'
assert hashes == {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in hashes}, 'Protected file changed'
for service, before in processes.items():
    command = subprocess.run(['systemctl', 'show', service], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert command.returncode == 0
    fields = dict(line.split('=', 1) for line in command.stdout.decode().splitlines() if '=' in line)
    assert before == {key: fields[key] for key in before}, 'Administrator service restarted'
registry = json.loads(Path('/var/lib/vps-panel/users.private.json').read_text())
assert len(registry['users']) == 2
members = []
identities = []
owner_state = json.loads(owner.read_text())
def identity(state):
    reality = state['base']['inbounds'][0]['streamSettings']['realitySettings']
    return (state['base']['inbounds'][0]['settings']['clients'][0]['id'], state['auto_id'],
            state['rule_token'], reality['privateKey'], state['public'], state['short'])
identities.append(identity(owner_state))
for user in registry['users']:
    user_id = user['id']
    assert re.fullmatch(r'[0-9a-f]{16}', user_id)
    config_directory = Path('/usr/local/etc/xray-members') / user_id
    config_path = config_directory / 'config.json'
    state_directory = Path('/var/lib/vps-panel/users') / user_id
    state_path = state_directory / 'state.private.json'
    for path, mode in [(config_directory, 0o700), (config_path, 0o600),
                       (state_directory, 0o700), (state_path, 0o600)]:
        stat = path.stat()
        assert not path.is_symlink() and stat.st_uid == 0 and (stat.st_mode & 0o777) == mode
    state = json.loads(state_path.read_text())
    config = json.loads(config_path.read_text())
    assert state['managed_hash'] == hashlib.sha256(config_path.read_bytes()).hexdigest()
    assert state['base']['inbounds'][0]['port'] == user['port'] == config['inbounds'][0]['port']
    identities.append(identity(state))
    service = 'xray-panel@' + user_id + '.service'
    values = subprocess.run(['systemctl', 'show', service], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    fields = dict(line.split('=', 1) for line in values.stdout.decode().splitlines() if '=' in line)
    assert fields['ActiveState'] == 'active' and fields['UnitFileState'] == 'enabled' and int(fields['MainPID']) > 0
    members.append({'username':user['username'], 'port':user['port'], 'active':True,
                    'root_private_files':True, 'config_matches_state':True,
                    'pid':fields['MainPID'], 'start_monotonic':fields['ExecMainStartTimestampMonotonic'],
                    'state_sha256':hashlib.sha256(state_path.read_bytes()).hexdigest(),
                    'config_sha256':hashlib.sha256(config_path.read_bytes()).hexdigest()})
for column in range(6):
    assert len({identity[column] for identity in identities}) == 3
print(json.dumps({'success':True, 'admin_complete_state_preserved':True,
                  'protected_hashes_preserved':True, 'admin_service_processes_preserved':True,
                  'independent_node_auto_and_rule_identities':True,
                  'independent_reality_keys_and_short_ids':True, 'members':members}))
'''


MEMBER_SERVICE = r'''
import hashlib, json, os, subprocess, sys, time, traceback
from pathlib import Path
sys.path.insert(0, '/opt/vps-panel')
from panel.server import Manager, atomic_write
from panel.accounts import Accounts
owner = Manager('/var/lib/vps-panel', '198.200.49.63', Path('/usr/local/etc/xray/config.json'),
                '/var/lib/vps-panel/base.private.yaml', False,
                origin='https://198-200-49-63.sslip.io:8443', base_path='/node-console/')
accounts = Accounts(owner, Path('/var/lib/vps-panel/auth.private.json'), demo=False)
record = next(user for user in accounts.records if user['username'] == 'user-a')
other = next(user for user in accounts.records if user['username'] == 'user-b')
manager = accounts.manager(record['id'])
assert manager.state['active_id'] == 'server' and not manager.state['exits']
original_state = manager.state_path.read_bytes()
original_config = manager.config_path.read_bytes()
untouched_paths = [owner.state_path, owner.config_path, accounts.users_path,
                   owner.directory / 'auth.private.json',
                   accounts.directory / other['id'] / 'state.private.json',
                   Path('/usr/local/etc/xray-members') / other['id'] / 'config.json']
untouched = {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in untouched_paths}
protected_services = ['xray.service','raksmart-hy2.service','caddy.service',
                      'vps-panel.service','xray-panel@' + other['id'] + '.service']
service_a = 'xray-panel@' + record['id'] + '.service'
def status(service):
    answer = subprocess.run(['systemctl','show',service], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    assert answer.returncode == 0
    fields = dict(line.split('=',1) for line in answer.stdout.decode().splitlines() if '=' in line)
    return {key:fields[key] for key in ['ActiveState','SubState','UnitFileState','MainPID','ExecMainStartTimestampMonotonic']}
before = {service:status(service) for service in protected_services}
before_a = status(service_a)
passed = False
try:
    identity = manager.start_job('apply','server')['job_id']
    deadline = time.monotonic() + 45
    while manager.jobs[identity]['status'] == 'running':
        assert time.monotonic() < deadline, 'Member service switch timed out'
        time.sleep(.1)
    assert manager.jobs[identity]['status'] == 'success', 'Member service switch failed'
    after_a = status(service_a)
    assert after_a['MainPID'] != before_a['MainPID'] and after_a['ExecMainStartTimestampMonotonic'] != before_a['ExecMainStartTimestampMonotonic']
    assert before == {service:status(service) for service in protected_services}, 'Another service changed'
    assert untouched == {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in untouched_paths}, 'Another private config changed'
    passed = True
finally:
    # Panel's cached member Manager stayed at the initial state throughout this
    # independent process, so restoring exact bytes returns both to agreement.
    assert manager.operation.acquire(timeout=40), 'Member operation did not settle for restoration'
    try:
        atomic_write(manager.config_path, original_config)
        atomic_write(manager.state_path, original_state)
        answer = subprocess.run(['systemctl','restart',service_a], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        assert answer.returncode == 0, 'Member restore restart failed'
        accounts._wait_ready(record)
    finally:
        manager.operation.release()
    assert manager.state_path.read_bytes() == original_state and manager.config_path.read_bytes() == original_config
    assert before == {service:status(service) for service in protected_services}, 'Another service changed during restore'
    assert untouched == {str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in untouched_paths}
assert passed
print(json.dumps({'success':True,'only_member_a_restarted':True,'member_a_exact_state_restored':True,
                  'member_a_exact_config_restored':True,'admin_and_member_b_unchanged':True,
                  'web_worker_not_restarted':True}))
'''


def preserved():
    report = json.loads((FOLDER / 'multiuser-update.json').read_text(encoding='utf-8'))
    backup = report['backup']
    live.require(isinstance(backup, str) and
                 re.fullmatch(r'/root/raksmart-proxy-deploy-20261009/multiuser-[A-Za-z0-9-]+/before', backup),
                 'Unexpected deployment backup location')
    program = 'BACKUP = ' + repr(backup) + '\n' + PRESERVATION
    client = connect()
    try:
        code, output, error = execute(client, "python3 - <<'MULTIUSER_PRESERVATION'\n" + program + '\nMULTIUSER_PRESERVATION\n', timeout=70)
        if code:
            (FOLDER / 'multiuser-preservation-error.private.log').write_text(output + '\n' + error, encoding='utf-8')
        live.require(code == 0, 'Complete owner, identities or process preservation failed')
        return json.loads(output)
    finally:
        client.close()


def member_service():
    client = connect()
    try:
        code, output, error = execute(client, "python3 - <<'MULTIUSER_MEMBER_SERVICE'\n" + MEMBER_SERVICE + '\nMULTIUSER_MEMBER_SERVICE\n', timeout=100)
        if code:
            (FOLDER / 'multiuser-member-service-error.private.log').write_text(output + '\n' + error, encoding='utf-8')
        live.require(code == 0, 'Member A real switch or complete restoration failed')
        return json.loads(output)
    finally:
        client.close()


def main():
    report = {'success':False, 'checked_at':datetime.now(timezone.utc).isoformat()}
    sessions = []
    member_a = None
    original_routing = None
    try:
        report['preservation_before'] = preserved()
        logins = [json.loads((FOLDER / name).read_text(encoding='utf-8')) for name in
                  ['panel-login.private.json', 'multiuser-user-a-login.private.json',
                   'multiuser-user-b-login.private.json']]
        sessions = [Session(login) for login in logins]
        owner, member_a, member_b = sessions
        live.require(owner.user['role'] == 'admin' and all(user.user['role'] == 'member' for user in sessions[1:]),
                     'Prepared accounts have incorrect roles')
        users = owner.json('GET', 'api/users')['users']
        live.require(len(users) == 3 and sorted(user['port'] for user in users) == [443, 1443, 2443],
                     'The three account entrances are incorrect')
        states = [session.json('GET', 'api/state') for session in sessions]
        profiles = [session.profile() for session in sessions]
        parsed = [yaml.safe_load(profile) for profile in profiles]
        for index, session in enumerate(sessions):
            live.require(states[index]['user']['id'] == session.user['id'], 'State returned another user')
            live.require(all(node['port'] == session.user['port'] for node in parsed[index]['proxies']),
                         'A profile contains another user entrance')
            live.require(session.json('GET', 'api/state?user_id=admin')['user']['id'] == session.user['id'],
                         'Client supplied user selection escaped session scope')
        live.require(not set(node['uuid'] for node in parsed[0]['proxies']) & set(node['uuid'] for node in parsed[1]['proxies']),
                     'Administrator and member proxy credentials overlap')
        live.require(not set(node['uuid'] for node in parsed[1]['proxies']) & set(node['uuid'] for node in parsed[2]['proxies']),
                     'Member proxy credentials overlap')
        admin_exit_ids = [entry['id'] for entry in states[0]['exits']]
        for session in sessions[1:]:
            session.json('GET', 'api/users', expected=403)
            for operation in ['create', 'reset-password', 'set-enabled']:
                session.json('POST', 'api/users/' + operation, {'id':'admin'}, expected=403)
            for identity in admin_exit_ids:
                session.json('POST', 'api/exits/save', {'id':identity}, expected=404)
                session.json('POST', 'api/exits/delete', {'id':identity}, expected=404)
            session.json('GET', 'api/jobs/' + owner.user['id'], expected=404)
        report['account_scope_and_admin_restrictions'] = True
        paths = []
        snapshots = []
        for profile in parsed:
            path = profile['rule-providers']['Custom Direct']['url'].split('/node-console/', 1)[1]
            paths.append(path)
            status, _, payload = live.request('GET', path)
            live.require(status == 200, 'A member rule subscription could not be loaded')
            snapshots.append(payload)
        live.require(len(set(paths)) == 3, 'Users share a custom rule subscription capability')
        original_routing = {key: states[1][key] for key in ['domains', 'direct_domains']}
        original_routing['mode'] = states[1]['routing_mode']
        marker = 'member-a-isolation.invalid'
        edited = dict(original_routing, direct_domains=list(original_routing['direct_domains']) + [marker], user_id='admin')
        member_a.json('POST', 'api/routing', edited)
        for index, path in enumerate(paths):
            status, _, payload = live.request('GET', path)
            live.require(status == 200 and ((marker.encode() in payload) if index == 1 else payload == snapshots[index]),
                         'Custom rules were applied outside their owning account')
        live.require(owner.json('GET', 'api/state')['direct_domains'] == states[0]['direct_domains'] and
                     member_b.json('GET', 'api/state')['direct_domains'] == states[2]['direct_domains'],
                     'A member rule edit changed another account')
        member_a.json('POST', 'api/routing', original_routing)
        original_routing = None
        live.require([session.profile() for session in sessions] == profiles, 'Profiles changed after temporary rule restoration')
        report['stable_independent_rule_subscriptions'] = True
        report['member_a_service_switch'] = member_service()
        live.require([session.profile() for session in sessions] == profiles, 'A service switch changed profile identities')
        for index, session in enumerate(sessions):
            name = 'multiuser-admin-clash.private.yaml' if index == 0 else 'multiuser-' + session.user['username'] + '-clash.private.yaml'
            (FOLDER / name).write_text(profiles[index], encoding='utf-8')
        reachable = []
        for port in [1443, 2443]:
            try:
                stream = live.physical_socket(port, timeout=4)
                stream.close()
                reachable.append({'port':port, 'public_tcp_reachable':True})
            except OSError:
                reachable.append({'port':port, 'public_tcp_reachable':False})
        report['member_public_ports'] = reachable
        report['preservation_after'] = preserved()
        report['success'] = True
        print(json.dumps(report))
    except BaseException:
        (FOLDER / 'multiuser-verification-error.private.log').write_text(traceback.format_exc(), encoding='utf-8')
        raise
    finally:
        if member_a is not None and original_routing is not None:
            member_a.json('POST', 'api/routing', original_routing)
        for session in sessions:
            session.logout()
        (FOLDER / 'multiuser-verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
