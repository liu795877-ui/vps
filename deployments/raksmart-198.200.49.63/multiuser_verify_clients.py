"""Use an isolated Mihomo to validate the two actual member REALITY nodes.

If platform ingress is blocked, SSH forwards provide a separate server-side
verification path. The public reachability outcome remains explicitly false.
No FlClash process, TUN, account, exit or server configuration is changed.
"""

from datetime import datetime, timezone
import copy
import json
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import threading
import time
import traceback
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

import yaml
import frontend_motion_access as live
from ssh_access import FOLDER, connect

BINARY = Path('C:/Users/LENOVO/.cockpit_tools/proxy-engine/release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe')
CURL = 'C:/Windows/System32/curl.exe'


def free_port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


class SSHForward:
    def __init__(self, client, member_port):
        self.client = client
        self.member_port = member_port
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(8)
        self.listener.settimeout(.5)
        self.port = self.listener.getsockname()[1]
        self.connections = []
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while not self.stop.is_set():
            try:
                connection, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                channel = self.client.get_transport().open_channel(
                    'direct-tcpip', ('127.0.0.1', self.member_port), peer, timeout=10)
            except Exception:
                connection.close()
                continue
            self.connections.append((connection, channel))
            threading.Thread(target=self.pump, args=(connection, channel), daemon=True).start()
            threading.Thread(target=self.pump, args=(channel, connection), daemon=True).start()

    def pump(self, source, target):
        try:
            while not self.stop.is_set():
                payload = source.recv(65536)
                if not payload:
                    return
                target.sendall(payload)
        except Exception:
            pass
        finally:
            source.close()
            target.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        for connection, channel in self.connections:
            connection.close()
            channel.close()


def main():
    report = {'success':False, 'checked_at':datetime.now(timezone.utc).isoformat(), 'samples':[]}
    folder = FOLDER / 'multiuser-client-validation' / secrets.token_hex(5)
    folder.mkdir(parents=True)
    process = None
    client = None
    forwards = []
    try:
        verified = json.loads((FOLDER / 'multiuser-verification.json').read_text(encoding='utf-8'))
        reachable = {item['port']:item['public_tcp_reachable'] for item in verified['member_public_ports']}
        live.require(set(reachable) == {1443, 2443}, 'Public reachability evidence is incomplete')
        profiles = [yaml.safe_load((FOLDER / ('multiuser-user-' + name + '-clash.private.yaml')).read_text(encoding='utf-8'))
                    for name in ['a', 'b']]
        full_syntax = []
        for index, profile in enumerate(profiles):
            syntax_directory = folder / ('full-member-' + ['a','b'][index])
            syntax_directory.mkdir()
            full = copy.deepcopy(profile)
            full.update({'mixed-port':free_port(), 'port':0, 'socks-port':0,
                         'allow-lan':False, 'bind-address':'127.0.0.1', 'tun':{'enable':False},
                         'interface-name':'WLAN', 'profile':{'store-selected':False,'store-fake-ip':False}})
            public_cache = FOLDER / 'smart-routing-validation/core-check'
            for provider_name, provider in full['rule-providers'].items():
                if provider.get('type') != 'http':
                    continue
                relative = Path(provider['path'])
                live.require(not relative.is_absolute() and '..' not in relative.parts,
                             'Unexpected rule cache path')
                destination = syntax_directory / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if provider_name.startswith('Custom '):
                    url = provider['url']
                    live.require(url.startswith(live.ORIGIN + '/node-console/rules/custom/'),
                                 'Unexpected member rule subscription origin')
                    status, _, payload = live.request('GET', url.split('/node-console/',1)[1])
                    live.require(status == 200, 'Member custom syntax cache could not load')
                    destination.write_bytes(payload)
                elif (public_cache / relative).is_file():
                    shutil.copyfile(str(public_cache / relative), str(destination))
            full_candidate = syntax_directory / 'complete-member.private.yaml'
            full_candidate.write_text(yaml.safe_dump(full, allow_unicode=True, sort_keys=False), encoding='utf-8')
            with (syntax_directory / 'syntax.private.log').open('w',encoding='utf-8') as syntax_log:
                syntax = subprocess.run([str(BINARY), '-t', '-d', str(syntax_directory), '-f', str(full_candidate)],
                                        stdout=syntax_log, stderr=subprocess.STDOUT, timeout=60,
                                        creationflags=live.NO_WINDOW)
            live.require(syntax.returncode == 0, 'Official Mihomo rejected a complete member smart profile')
            full_syntax.append({'account':'user-' + ['a','b'][index], 'official_core_accepted':True,
                                'complete_smart_profile':True, 'rule_provider_count':len(full['rule-providers'])})
        report['complete_member_profile_syntax'] = full_syntax
        nodes = [copy.deepcopy(next(node for node in profile['proxies'] if node['name'] == 'AUTO · 网页切换'))
                 for profile in profiles]
        live.require([node['port'] for node in nodes] == [1443, 2443], 'Member AUTO ports are incorrect')
        public = all(reachable.values())
        if not public:
            client = connect()
            for node in nodes:
                forward = SSHForward(client, node['port'])
                forwards.append(forward)
                node.update(server='127.0.0.1', port=forward.port)
        for name, node in zip(['member-a', 'member-b'], nodes):
            node['name'] = name
        wrong_a = copy.deepcopy(nodes[0])
        wrong_a.update(name='member-a-wrong-uuid', uuid=nodes[1]['uuid'])
        wrong_b = copy.deepcopy(nodes[1])
        wrong_b.update(name='member-b-wrong-uuid', uuid=nodes[0]['uuid'])
        test_nodes = nodes + [wrong_a, wrong_b]
        proxy_port, control_port = free_port(), free_port()
        while proxy_port == control_port:
            control_port = free_port()
        secret = secrets.token_urlsafe(24)
        config = {'mixed-port':proxy_port, 'port':0, 'socks-port':0,
                  'allow-lan':False, 'bind-address':'127.0.0.1', 'ipv6':False,
                  'tun':{'enable':False}, 'log-level':'warning', 'mode':'rule',
                  'external-controller':'127.0.0.1:' + str(control_port), 'secret':secret,
                  'profile':{'store-selected':False, 'store-fake-ip':False},
                  'proxies':test_nodes,
                  'proxy-groups':[{'name':'MEMBER-VERIFY','type':'select',
                                   'proxies':[node['name'] for node in test_nodes]}],
                  'rules':['MATCH,MEMBER-VERIFY']}
        if public:
            config['interface-name'] = 'WLAN'
        candidate = folder / 'members-client.private.yaml'
        candidate.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding='utf-8')
        with (FOLDER / 'multiuser-clients.private.log').open('w', encoding='utf-8') as log:
            syntax = subprocess.run([str(BINARY), '-t', '-d', str(folder), '-f', str(candidate)],
                                    stdout=log, stderr=subprocess.STDOUT, timeout=30, creationflags=live.NO_WINDOW)
            live.require(syntax.returncode == 0, 'Official Mihomo rejected the isolated member configuration')
            process = subprocess.Popen([str(BINARY), '-d', str(folder), '-f', str(candidate)],
                                       stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                       creationflags=live.NO_WINDOW)
            opener = build_opener(ProxyHandler({}))
            controller = 'http://127.0.0.1:' + str(control_port)
            def api(path, method='GET', data=None):
                body = json.dumps(data).encode() if data is not None else None
                headers = {'Authorization':'Bearer ' + secret, 'Content-Type':'application/json'}
                query = Request(controller + path, data=body, method=method, headers=headers)
                with opener.open(query, timeout=5) as response:
                    payload = response.read()
                    return json.loads(payload) if payload else None
            deadline = time.monotonic() + 20
            while True:
                live.require(process.poll() is None, 'Isolated member client exited')
                try:
                    api('/version')
                    break
                except OSError:
                    live.require(time.monotonic() < deadline, 'Isolated member client controller did not start')
                    time.sleep(.2)
            for node in test_nodes:
                api('/proxies/' + quote('MEMBER-VERIFY', safe=''), 'PUT', {'name':node['name']})
                expected_success = node in nodes
                for attempt in range(3 if expected_success else 1):
                    outcome = subprocess.run([CURL, '--proxy','socks5h://127.0.0.1:' + str(proxy_port),
                                              '--noproxy','', '--connect-timeout','6', '--max-time','12' if expected_success else '8',
                                              '--silent','--show-error','https://api.ipify.org'],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=18,
                                             creationflags=live.NO_WINDOW)
                    if outcome.returncode == 0 or not expected_success:
                        break
                    log.write('Bounded retry ' + node['name'] + ': ' + str(attempt + 1) + '\n')
                    log.flush()
                    if attempt < 2:
                        time.sleep(.3)
                if expected_success:
                    live.require(outcome.returncode == 0 and outcome.stdout.decode('ascii').strip() == live.IP,
                                 'A real member AUTO connection could not use the server egress')
                    sample = {'account':node['name'], 'server_egress_verified':True, 'observed_ip':live.IP}
                else:
                    live.require(outcome.returncode != 0, 'One member UUID was accepted by another member entrance')
                    sample = {'account':node['name'].replace('-wrong-uuid',''), 'other_member_uuid_rejected':True}
                report['samples'].append(sample)
                log.write(json.dumps(sample) + '\n')
                log.flush()
        report.update(success=True, public_proxy_connections_verified=public,
                      server_internal_proxy_connections_verified=True,
                      transport='physical_wlan' if public else 'physical_wlan_ssh_forward',
                      public_ports=verified['member_public_ports'], credentials_not_interchangeable=True)
        print(json.dumps(report))
    except BaseException:
        (FOLDER / 'multiuser-clients-error.private.log').write_text(traceback.format_exc(), encoding='utf-8')
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for forward in forwards:
            forward.close()
        if client is not None:
            client.close()
        (FOLDER / 'multiuser-clients-verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
