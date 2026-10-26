"""Bounded server-direct Fast target and Cloudflare destination diagnosis.

Fresh signed URLs are fetched via existing FlClash and passed only via SSH
stdin to an in-memory remote program. No URL/query/token/config copies are
written on the server. No system, proxy, exit or account setting changes.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import time

import benchmark_fast_regression as fast
import verify_hy2_clients as helpers


REMOTE = r'''
import concurrent.futures, hashlib, json, socket, ssl, sys, time
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPSHandler, Request

plan = json.loads(sys.stdin.read(32768))
assert isinstance(plan, dict) and set(plan) == {'targets', 'cloudflare'}
assert type(plan['cloudflare']) is bool and len(plan['targets']) == 4
for target in plan['targets']:
    address = urlsplit(target)
    assert address.scheme == 'https' and address.hostname.endswith('.nflxvideo.net')
    assert address.path == '/speedtest/range/0-16777215' and not address.username and not address.password
    assert address.port in (None, 443)

def transfer(url, cap, deadline):
    started = time.monotonic()
    address = urlsplit(url)
    result = {'hostname': address.hostname, 'maximum_payload_bytes': cap, 'actual_download_bytes': 0,
              'http_code': None, 'tls_certificate_verification': True}
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()))
    response = None
    try:
        remaining = deadline - time.monotonic()
        assert remaining > 0
        response = opener.open(Request(url, headers={'User-Agent':'Mozilla/5.0 FastDiagnostic',
            'Range':'bytes=0-' + str(cap-1)}), timeout=remaining)
        result['http_code'] = response.status
        result['headers_ready_ms'] = round((time.monotonic()-started)*1000,3)
        assert response.status in (200,206)
        actual = 0
        while actual < cap and time.monotonic() < deadline:
            remaining = max(.001, deadline-time.monotonic())
            try:
                response.fp.raw._sock.settimeout(remaining)
            except AttributeError:
                pass
            data = response.read(1 if actual == 0 else min(65536,cap-actual))
            if not data:
                break
            actual += len(data)
            result['actual_download_bytes'] = actual
            if actual == 1:
                result['ttfb_ms'] = round((time.monotonic()-started)*1000,3)
        result['completed_full_block'] = actual == cap
        result['bounded_partial'] = 0 < actual < cap
        result['error_category'] = 'none' if actual == cap else 'window-end-or-eof'
    except Exception as error:
        result.update(completed_full_block=False, bounded_partial=result['actual_download_bytes'] > 0,
                      error_category='timeout' if isinstance(error,(TimeoutError,socket.timeout)) else type(error).__name__)
    finally:
        if response is not None:
            response.close()
    elapsed = time.monotonic()-started
    result['wall_seconds'] = round(elapsed,4)
    result['response_payload_received'] = result['actual_download_bytes'] > 0 and result['http_code'] in (200,206)
    result['observed_mbps_including_startup'] = round(result['actual_download_bytes']*8/elapsed/1e6,3)
    return result

started = time.monotonic()
deadline = started+12
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    jobs = [pool.submit(transfer,url,16777216,deadline) for url in plan['targets']]
    rows = [job.result() for job in jobs]
elapsed = time.monotonic()-started
actual = sum(row['actual_download_bytes'] for row in rows)
result = {'fast':{'parallel_requests':4,'actual_download_bytes':actual,'maximum_payload_bytes':67108864,
    'elapsed_seconds':round(elapsed,4),'observed_server_direct_mbps_including_startup':round(actual*8/elapsed/1e6,3),
    'requests':rows,'full_blocks':sum(row['completed_full_block'] for row in rows),
    'payload_successes':sum(row['response_payload_received'] for row in rows)},
    'proxy_used':False,'configuration_changes':0,'url_tokens_saved':False,'payload_files_written':0,
    'method_scope':'Server-direct verified HTTPS with stdlib reader; bounded payload/window, not browser Fast score.'}
if plan['cloudflare']:
    result['cloudflare']=transfer('https://speed.cloudflare.com/__down?bytes=8388608',8388608,time.monotonic()+12)
result['success']=all(row['response_payload_received'] for row in rows)
print(json.dumps(result))
'''


def run(args):
    report_path = helpers.FOLDER / args.report
    report = {'success': False, 'started_at': fast.base.utc(), 'configuration_changes': 0,
              'credential_changes': 0, 'exit_changes': 0, 'signed_urls_saved': False, 'tokens_saved': False}
    ssh, sftp = None, None
    stage = 'offline-gate'
    try:
        ast.parse(REMOTE, feature_version=(3,6))
        report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['remote_program_sha256'] = hashlib.sha256(REMOTE.encode()).hexdigest()
        if args.check_local:
            value=fast.bounded_url('https://ipv4-synthetic.nflxvideo.net/speedtest?synthetic=only')
            helpers.require('/speedtest/range/0-16777215?' in value,'Range fixture failed')
            report.update(success=True, offline_check=True, server_requests=0)
            return report
        helpers.require(not report_path.exists(), 'Report exists; preserve evidence with another report name')
        stage = 'targets-discovery'
        targets, metadata = fast.discover()
        report['discovery'] = metadata
        payload = {'targets':[fast.bounded_url(item['url']) for item in targets],'cloudflare':args.cloudflare}
        helpers.require(len(json.dumps(payload)) < 32768,'Target stdin payload too large')
        stage = 'read-only-accounts-before'
        ssh=helpers.connect()
        sftp=ssh.open_sftp()
        sftp.get_channel().settimeout(20)
        accounts,before_store=helpers.collect_accounts(sftp)
        report['accounts_before_sha256']=helpers.fingerprint([a['settings_hash'] for a in accounts])
        stage='server-direct-bounded-downloads'
        fast.base.emit('phase-start',stage,maximum_fast_payload_bytes=67108864,cloudflare=args.cloudflare)
        channel=ssh.get_transport().open_session(timeout=10)
        channel.settimeout(40)
        channel.exec_command('python3 -c '+shlex.quote(REMOTE))
        channel.sendall(json.dumps(payload).encode())
        channel.shutdown_write()
        output,error=bytearray(),bytearray()
        deadline=time.monotonic()+45
        while not channel.exit_status_ready() or channel.recv_ready() or channel.recv_stderr_ready():
            helpers.require(time.monotonic()<deadline,'Remote bounded measurement timeout')
            if channel.recv_ready():output.extend(channel.recv(65536))
            if channel.recv_stderr_ready():error.extend(channel.recv_stderr(65536))
            helpers.require(len(output)<65536 and len(error)<65536,'Unexpected remote output size')
            time.sleep(.05)
        code=channel.recv_exit_status()
        channel.close()
        helpers.require(code==0,'Remote bounded diagnostic failed')
        report['server_direct']=json.loads(output)
        report['server_direct']['fast']['target_regions']=metadata['targets']
        stage='read-only-accounts-after'
        after_store=helpers.ledger(sftp)
        registry=helpers.private_json(sftp,helpers.OWNER+'/users.private.json')
        records={'admin':next(a for a in accounts if a['id']=='admin')['record'],**{a['id']:a for a in registry['users']}}
        after_hashes=[helpers.settings_hash(helpers.private_json(sftp,a['state_path']),records[a['id']],after_store)
                      for a in accounts]
        report['all_account_settings_preserved']=all(value==account['settings_hash'] for value,account in zip(after_hashes,accounts))
        report['accounts_after_sha256']=helpers.fingerprint(after_hashes)
        report['success']=report['all_account_settings_preserved'] and report['server_direct']['success']
        fast.base.emit('phase-end','server-direct',success=report['success'],
                       fast_mbps=report['server_direct']['fast']['observed_server_direct_mbps_including_startup'])
        return report
    except Exception as error:
        report.update(failure_stage=stage,error_type=type(error).__name__)
        if isinstance(error,fast.SafeFailure):report['safe_error_detail']=error.safe_detail
        return report
    finally:
        if sftp is not None:sftp.close()
        if ssh is not None:ssh.close()
        report['remote_payload_files_written']=0
        report['finished_at']=fast.base.utc()
        if args.run and not report_path.exists():
            report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run',action='store_true')
    group.add_argument('--check-local',action='store_true')
    parser.add_argument('--cloudflare',action='store_true')
    parser.add_argument('--report',default='fast-server-direct-current.json',type=lambda value:value
                        if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}\.json',value) else parser.error('Safe JSON basename required'))
    result=run(parser.parse_args())
    print(json.dumps(result),flush=True)
    raise SystemExit(0 if result.get('success') else 1)
