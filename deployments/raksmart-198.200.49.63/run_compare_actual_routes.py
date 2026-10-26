"""One bounded sequential Fast comparison of four existing server-only routes.

Current private identities stay in memory apart from ACL-protected temporary
Mihomo candidates, which are removed. No web exit or production setting changes.
This compares today's server exits, not an unknown historical 200 Mbps node.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import ssl
import time

import yaml
import benchmark_fast_regression as fast
import benchmark_hy2_latency as base
import compare_server_configs_live as comparison
import verify_hy2_clients as helpers


HOST158 = '198.200.49.158'
HOST63 = '198.200.49.63'
STATE = '/var/lib/vps-panel/state.private.json'
HY2_158 = '/usr/local/etc/raksmart-hy2/server.yaml'
MAX_PER_PATH = fast.MAX_BLOCK_BYTES * fast.MAX_TARGETS

GUARD = r'''
import glob,hashlib,json,re,subprocess
from datetime import datetime,timezone
from pathlib import Path
rows=subprocess.check_output(['systemctl','list-units','--all','--type=service','--plain','--no-legend'],timeout=8).decode()
services={}
paths=set(['/var/lib/vps-panel/state.private.json','/var/lib/vps-panel/auth.private.json','/var/lib/vps-panel/users.private.json','/var/lib/vps-panel/hy2.private.json','/usr/local/etc/xray/config.json','/usr/local/etc/raksmart-hy2/server.yaml'])
paths.update(glob.glob('/var/lib/vps-panel/users/*/state.private.json'))
paths.update(glob.glob('/usr/local/etc/raksmart-hy2/accounts/*.yaml'))
paths.update(glob.glob('/usr/local/etc/raksmart-hy2/*.pem'))
paths.update(glob.glob('/var/lib/vps-panel/hy2-*.pem'))
for line in rows.splitlines():
    name=line.split()[0]
    if name in ('xray.service','raksmart-hy2.service','vps-panel.service','caddy.service') or re.fullmatch(r'(raksmart-hy2@[0-9]+|xray-panel@[a-f0-9]+)\.service',name):
        text=subprocess.check_output(['systemctl','show',name,'--property=MainPID','--property=ExecMainStartTimestampMonotonic','--property=ActiveState','--property=SubState'],timeout=5).decode()
        item=dict(x.split('=',1) for x in text.splitlines() if '=' in x)
        services[name]=item
        pid=int(item.get('MainPID','0'))
        if pid:
            for value in Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0'):
                if value.startswith(b'/') and value.endswith((b'.yaml',b'.yml',b'.json')):paths.add(value.decode())
hashes={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in sorted(paths) if Path(p).is_file()}
traffic=Path('/var/lib/vps-panel/traffic.private.json')
store=json.loads(traffic.read_text()) if traffic.is_file() else {'users':{}}
month=datetime.now(timezone.utc).strftime('%Y-%m')
usage={}
for identity,user in store.get('users',{}).items():
    totals=user.get('months',{}).get(month,{})
    usage[identity]={'quota_bytes':user.get('quota_bytes',0),'rate_bps':user.get('rate_bps',0),'up_bytes':totals.get('up_bytes',0),'down_bytes':totals.get('down_bytes',0)}
print(json.dumps({'services':services,'protected_sha256':hashes,'usage':usage,'month':month}))
'''


def raw(sftp, path):
    with sftp.open(path, 'rb') as stream:
        return stream.read()


def guard(ssh, access):
    code, output, _ = access.execute(ssh, 'python3 -c ' + shlex.quote(GUARD), timeout=40)
    helpers.require(code == 0, 'Read-only protected snapshot failed')
    return json.loads(output)


def quota_gate(snapshot):
    # Reserve two payload paths plus metadata/identity traffic; no quota bypass.
    user = snapshot['usage'].get('admin', {})
    quota = user.get('quota_bytes', 0)
    used = user.get('up_bytes', 0) + user.get('down_bytes', 0)
    helpers.require(not quota or quota - used >= 2 * MAX_PER_PATH + 8 * 1048576,
                    'Insufficient remaining quota for this bounded comparison')


def validate_server_route(node, runtime, identity):
    inbounds = [item for item in runtime.get('inbounds', []) if item.get('port') == 443
                and item.get('protocol') == 'vless']
    helpers.require(len(inbounds) == 1, 'Unique current VLESS entrance required')
    inbound = inbounds[0]
    clients = [item for item in inbound['settings']['clients'] if item.get('id') == identity]
    helpers.require(len(clients) == 1 and node.get('uuid') == identity,
                    'Current direct VLESS identity does not match the running entrance')
    stream = inbound.get('streamSettings', {})
    reality = stream.get('realitySettings', {})
    helpers.require(node.get('type') == 'vless' and node.get('tls') is True
                    and node.get('flow') == clients[0].get('flow')
                    and stream.get('security') == 'reality'
                    and node.get('servername') in reality.get('serverNames', [])
                    and node.get('reality-opts', {}).get('short-id') in reality.get('shortIds', [])
                    and node.get('reality-opts', {}).get('public-key')
                    and not node.get('skip-cert-verify') and not node.get('dialer-proxy'),
                    'Current direct VLESS TLS identity is inconsistent')
    email = clients[0].get('email')
    candidates = [rule for rule in runtime.get('routing', {}).get('rules', [])
                  if email and email in rule.get('user', []) and rule.get('network') in (None, 'tcp')]
    if candidates:
        helpers.require(all(rule.get('outboundTag') == 'direct' for rule in candidates),
                        'Existing VLESS identity routes through a static exit')
    else:
        # The original primary user is not a web AUTO/fixed-exit user. Its
        # ordinary TCP requests must reach the explicit default direct outbound.
        helpers.require(runtime.get('outbounds', [{}])[0].get('protocol') == 'freedom',
                        'Original direct user does not have a server default exit')
        private_cidrs = {'0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                         '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.18.0.0/15',
                         '224.0.0.0/4', '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7',
                         'fe80::/10', 'ff00::/8', 'geoip:private'}
        for rule in runtime.get('routing', {}).get('rules', []):
            if rule.get('outboundTag') != 'direct' and not rule.get('user'):
                inbound_excluded = (rule.get('inboundTag') and inbound.get('tag') not in rule['inboundTag'])
                private_block = (rule.get('outboundTag') == 'block' and rule.get('ip')
                                 and set(rule['ip']).issubset(private_cidrs))
                helpers.require(inbound_excluded or rule.get('network') == 'udp' or private_block,
                                'Unclassified public TCP route for original user')
    return node


def collect158(sftp):
    state = helpers.private_json(sftp, STATE)
    profile = yaml.safe_load(state['profile'])
    runtime = json.loads(raw(sftp, '/usr/local/etc/xray/config.json'))
    templates = [node for node in profile.get('proxies', []) if node.get('name') == 'AUTO · 网页切换'
                 and node.get('type') == 'vless' and node.get('server') == HOST158 and node.get('port') == 443
                 and node.get('uuid') == state.get('auto_id')]
    helpers.require(len(templates) == 1, 'Unique current published VLESS template required')
    original = state.get('base', {}).get('inbounds', [{}])[0].get('settings', {}).get('clients', [])
    helpers.require(len(original) >= 1, 'Original server direct user unavailable')
    direct_identity = original[0].get('id')
    helpers.require(direct_identity and direct_identity != state.get('auto_id'),
                    'Original direct identity is indistinguishable from AUTO')
    tcp = copy.deepcopy(templates[0])
    tcp.update(name='EXISTING-158-SERVER-DIRECT', uuid=direct_identity)
    validate_server_route(tcp, runtime, direct_identity)
    config = yaml.safe_load(raw(sftp, HY2_158))
    helpers.require(config.get('listen') == '0.0.0.0:443'
                    and config.get('auth', {}).get('type') == 'password'
                    and len(config.get('outbounds', [])) == 1
                    and config['outbounds'][0].get('type') == 'direct',
                    'Existing .158 HY2 is not a unique direct server entrance')
    cert_path = config.get('tls', {}).get('cert')
    helpers.require(isinstance(cert_path, str) and cert_path.startswith('/usr/local/etc/raksmart-hy2/')
                    and cert_path.endswith('.pem'), 'Unexpected existing HY2 certificate path')
    cert = raw(sftp, cert_path)
    certificate_sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.decode())).hexdigest()
    hy2 = {'name': 'EXISTING-158-HY2-DIRECT', 'type': 'hysteria2', 'server': HOST158, 'port': 443,
           'password': config['auth']['password'], 'sni': 'raksmart-hy2.local', 'skip-cert-verify': False,
           'fingerprint': certificate_sha, 'udp': False, 'bbr-profile': 'standard'}
    return tcp, hy2, {'vless_identity_source': 'current original primary user from state.base, matched to running Xray',
                      'vless_transport_source': 'current published VLESS TLS template; only existing direct UUID substituted',
                      'hy2_identity_source': 'current official independent HY2 runtime and pinned certificate',
                      'current_web_auto_not_used': True, 'expected_public_egress': HOST158}


def safely_cleanup(action, label, errors):
    try:
        action()
    except BaseException as error:
        errors.append(label + ':' + type(error).__name__)


def run(args):
    report_path = helpers.FOLDER / args.report
    directory = base.TEMP_ROOT / secrets.token_hex(8)
    resources, clients, owned_curls, before = {}, [], [], {}
    started = time.monotonic()
    report = {'success': False, 'started_at': base.utc(), 'server_changes': 0, 'exit_changes': 0,
              'credential_changes': 0, 'signed_urls_saved': False, 'tokens_saved': False,
              'paths': [], 'cleanup_errors': [], 'preservation_errors': []}
    stage = 'local-gates'
    try:
        helpers.require(not report_path.exists(), 'Preserve existing reports; distinct basename required')
        helpers.require(not base.TEMP_ROOT.is_symlink(), 'Unsafe private parent')
        report['private_directory_acl'] = base.make_private(directory)
        report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['method'] = {'same_four_signed_targets': True, 'strictly_sequential_paths': True,
                            'path_count': 4, 'maximum_content_bytes_all_paths': 4 * MAX_PER_PATH,
                            'maximum_content_bytes_per_path': MAX_PER_PATH, 'maximum_seconds_per_path': 12,
                            'parallel_requests_per_path': 4, 'reader_overflow_detection_tolerance_bytes_per_request': 1,
                            'overflow_responses_rejected': True, 'physical_interface': 'WLAN',
                            'server_own_exits_only': True,
                            'scope': 'current isolated official Mihomo paths; not historical device or unrestricted browser score'}
        if args.check_local:
            for index, node in enumerate(helpers.synthetic_nodes()):
                client = base.BenchClient(directory / ('synthetic' + str(index)), node, started)
                clients.append(client)
                client.syntax()
                client.close()
            report.update(success=True, offline_syntax_verified=True, server_requests=0)
            return report
        stage = 'live-read-only-snapshots'
        for host in (HOST158, HOST63):
            access = comparison.load_access(host)
            ssh = access.connect()
            resources[host] = {'access': access, 'ssh': ssh, 'sftp': None}
            sftp = ssh.open_sftp()
            resources[host]['sftp'] = sftp
            sftp.get_channel().settimeout(20)
            before[host] = guard(ssh, access)
            quota_gate(before[host])
        tcp158, hy2158, report['158_sources'] = collect158(resources[HOST158]['sftp'])
        accounts63, _ = helpers.collect_accounts(resources[HOST63]['sftp'])
        admin63 = next(item for item in accounts63 if item['id'] == 'admin')
        helpers.require(admin63['expected_ip'] == HOST63, 'Current .63 admin AUTO must be server direct')
        runtime63 = json.loads(raw(resources[HOST63]['sftp'], '/usr/local/etc/xray/config.json'))
        validate_server_route(admin63['nodes']['xray'], runtime63, admin63['nodes']['xray']['uuid'])
        candidates = [('158-vless-server-direct', HOST158, tcp158),
                      ('158-official-hy2-server-direct', HOST158, hy2158),
                      ('63-vless-auto-server-direct', HOST63, admin63['nodes']['xray']),
                      ('63-hy2-auto-server-direct', HOST63, admin63['nodes']['hy2'])]
        stage = 'syntax-all-current-nodes'
        for index, (_, _, node) in enumerate(candidates):
            client = base.BenchClient(directory / ('path' + str(index)), node, started)
            clients.append(client)
            client.syntax()
            client.close()
        stage = 'shared-fast-target-discovery'
        targets, report['discovery'] = fast.discover()
        for target in targets:
            fast.bounded_url(target['url'])
        for (label, host, _), client in zip(candidates, clients):
            stage = label + '-identity'
            base.emit('phase-start', stage, expected_public_egress=host)
            client.start(time.monotonic() + 35)
            identity = client.request('light', host, max_time=10)
            report['paths'].append({'label': label, 'identity': identity, 'expected_public_egress': host})
            helpers.require(identity['success'], 'Existing server route failed its required public egress check')
            stage = label + '-bounded-fast'
            result = fast.path_measurement(label, client.proxy_port, targets, owned_curls)
            helpers.require(all((item.get('curl_reported_download_bytes') or 0) <= fast.MAX_BLOCK_BYTES
                                for item in result['requests']), 'Peer exceeded response content cap')
            report['paths'][-1].update(result)
            client.close()
        report['success'] = all(item.get('success') and item['identity']['success'] for item in report['paths'])
        return report
    except BaseException as error:
        report.update(failure_stage=stage, error_type=type(error).__name__, success=False)
        if isinstance(error, fast.SafeFailure):
            report['safe_error'] = error.safe_detail
        return report
    finally:
        for index, process in enumerate(owned_curls):
            if process.poll() is None:
                safely_cleanup(process.kill, 'curl-kill-' + str(index), report['cleanup_errors'])
            safely_cleanup(lambda p=process: p.communicate(timeout=4), 'curl-reap-' + str(index), report['cleanup_errors'])
        for index, client in enumerate(clients):
            safely_cleanup(client.close, 'client-close-' + str(index), report['cleanup_errors'])
        report['preservation'] = {}
        for host, value in resources.items():
            if host in before:
                try:
                    after = guard(value['ssh'], value['access'])
                    prior = before[host]
                    limits = lambda snapshot: {identity: {key: user.get(key, 0) for key in ('quota_bytes', 'rate_bps')}
                                               for identity, user in snapshot['usage'].items()}
                    preserved = {'protected_files_unchanged': prior['protected_sha256'] == after['protected_sha256'],
                                 'service_epochs_unchanged': prior['services'] == after['services'],
                                 'all_account_limits_unchanged': limits(prior) == limits(after),
                                 'monthly_totals_not_decreased': prior['month'] == after['month'] and all(
                                     after['usage'].get(identity, {}).get(key, 0) >= user.get(key, 0)
                                     for identity, user in prior['usage'].items() for key in ('up_bytes', 'down_bytes')),
                                 'before_protected_sha256': prior['protected_sha256'],
                                 'after_protected_sha256': after['protected_sha256']}
                    report['preservation'][host] = preserved
                    if not all(preserved[key] for key in ('protected_files_unchanged', 'service_epochs_unchanged',
                                                         'all_account_limits_unchanged', 'monthly_totals_not_decreased')):
                        report['success'] = False
                except BaseException as error:
                    report['preservation_errors'].append(host + ':' + type(error).__name__)
            for resource in ('sftp', 'ssh'):
                if value.get(resource) is not None:
                    safely_cleanup(value[resource].close, host + '-' + resource, report['cleanup_errors'])
        def remove_private():
            helpers.require(directory.resolve().parent == base.TEMP_ROOT.resolve() and not directory.is_symlink()
                            and re.fullmatch(r'[a-f0-9]{16}', directory.name), 'Unsafe scratch removal path')
            if directory.exists():
                shutil.rmtree(str(directory))
        safely_cleanup(remove_private, 'private-directory', report['cleanup_errors'])
        report['own_clients_terminated'] = all(client.process is None or client.process.poll() is not None for client in clients)
        report['own_curl_processes_terminated'] = all(process.poll() is not None for process in owned_curls) and all(
            process.poll() is not None for client in clients for process in client.all_children)
        report['temporary_private_files_removed'] = not directory.exists()
        if report['cleanup_errors'] or report['preservation_errors'] or not all(report[key] for key in (
                'own_clients_terminated', 'own_curl_processes_terminated', 'temporary_private_files_removed')):
            report['success'] = False
        report['finished_at'] = base.utc()
        if args.run and not report_path.exists():
            report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--run', action='store_true')
    mode.add_argument('--check-local', action='store_true')
    parser.add_argument('--report', default='actual-routes-158-vs-63-current.json')
    args = parser.parse_args()
    helpers.require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}\.json', args.report), 'Safe JSON report basename required')
    result = run(args)
    print(json.dumps({'success': result['success'], 'failure_stage': result.get('failure_stage'),
                      'paths': [{'label': item['label'], 'mbps': item.get('observed_download_mbps_including_startup'),
                                 'server_egress_verified': item['identity']['success']} for item in result['paths']],
                      'cleanup_errors': result['cleanup_errors'], 'preservation_errors': result['preservation_errors'],
                      'report': args.report}), flush=True)
    raise SystemExit(0 if result['success'] else 1)
