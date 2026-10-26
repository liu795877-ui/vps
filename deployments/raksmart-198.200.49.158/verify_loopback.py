"""Verify the actual deployed config and test local REALITY without cloud ingress."""
import argparse
import json
import re
import shlex
from ssh_access import connect, execute, FOLDER

stage = '/root/raksmart-proxy-deploy-20261009'
parser = argparse.ArgumentParser()
parser.add_argument('--debug-server', action='store_true')
parser.add_argument('--target')
parser.add_argument('--brief', action='store_true')
args = parser.parse_args()
if args.target and not args.debug_server:
    parser.error('--target requires --debug-server')
client = connect()
try:
    config = json.loads((FOLDER/'client-test.private.json').read_text(encoding='utf-8'))
    config['log']['loglevel'] = 'info'
    config['outbounds'][0]['settings']['vnext'][0]['address'] = '127.0.0.1'
    if args.debug_server:
        config['outbounds'][0]['settings']['vnext'][0]['port'] = 25443
    if args.target:
        config['outbounds'][0]['streamSettings']['realitySettings']['serverName'] = args.target
    config['inbounds'][0]['port'] = 17980
    with client.open_sftp() as sftp:
        with sftp.open('/usr/local/etc/xray/config.json', 'r') as remote:
            actual = json.loads(remote.read().decode('utf-8'))
        expected = json.loads((FOLDER/'server.private.json').read_text(encoding='utf-8'))
        if args.debug_server:
            debug_server = json.loads(json.dumps(expected))
            debug_server['inbounds'][0]['port'] = 25443
            debug_server['inbounds'][0]['listen'] = '127.0.0.1'
            debug_server['log']['loglevel'] = 'debug'
            debug_server['inbounds'][0]['streamSettings']['realitySettings']['show'] = True
            if args.target:
                reality = debug_server['inbounds'][0]['streamSettings']['realitySettings']
                reality['target'] = args.target + ':443'
                reality['serverNames'] = [args.target]
            with sftp.open(stage+'/debug-server.private.json', 'w') as remote:
                remote.write(json.dumps(debug_server))
            sftp.chmod(stage+'/debug-server.private.json', 0o600)
        print('DEPLOYED_CONFIG_MATCHES_LOCAL', actual == expected, flush=True)
        with sftp.open(stage+'/loopback-client.private.json', 'w') as remote:
            remote.write(json.dumps(config))
        sftp.chmod(stage+'/loopback-client.private.json', 0o600)
    command = '''
set -u
'''
    if args.debug_server:
        command += '''
/usr/local/bin/xray run -config /root/raksmart-proxy-deploy-20261009/debug-server.private.json >/root/raksmart-proxy-deploy-20261009/debug-server.log 2>&1 &
debug_pid=$!
'''
    command += '''
/usr/local/bin/xray run -config /root/raksmart-proxy-deploy-20261009/loopback-client.private.json >/root/raksmart-proxy-deploy-20261009/loopback-client.log 2>&1 &
test_pid=$!
trap 'kill "$test_pid" ${debug_pid:-} 2>/dev/null || true' EXIT
sleep 1
curl --proxy socks5h://127.0.0.1:17980 --noproxy '' --connect-timeout 10 --max-time 20 -sS -w '\nHTTP_CODE:%{http_code}\n' https://api.ipify.org
'''
    code, output, error = execute(client, command, timeout=30)
    print('LOOPBACK_CURL_EXIT', code)
    print(output)
    print(error)
    with client.open_sftp() as sftp:
        with sftp.open(stage+'/loopback-client.log','r') as remote:
            log = remote.read().decode('utf-8',errors='replace')
        if args.debug_server:
            with sftp.open(stage+'/debug-server.log','r') as remote:
                log += '\nSERVER DEBUG\n' + remote.read().decode('utf-8',errors='replace')
    identity = json.loads((FOLDER/'identity.private.json').read_text(encoding='utf-8'))
    for value in identity.values():
        log = log.replace(value, '[REDACTED]')
    log = re.sub(r'(hs\.c\.(?:AuthKey\[:16\]|ClientShortId):) \[[^\]]*\]',
                 r'\1 [REDACTED]', log)
    if not args.brief:
        print(log)
    report_name = 'loopback-debug-verification.json' if args.debug_server else 'loopback-verification.json'
    (FOLDER/report_name).write_text(json.dumps({
        'deployed_config_matches_local': actual == expected,
        'exit_code': code, 'stdout': output, 'stderr': error, 'client_log': log,
    },indent=2),encoding='utf-8')
finally:
    client.close()
