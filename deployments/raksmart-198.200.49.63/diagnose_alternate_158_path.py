"""Bounded existing .158 HY2 alternate path, read current private identity.

No old draft identities are used. No .158/.63/user config or exit changes.
One 8 MiB Cloudflare download, at most 12 seconds, follows an IP identity check.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import ssl
import time

import yaml
import benchmark_hy2_latency as base
import benchmark_fast_regression as fast
import verify_hy2_clients as helpers


HOST='198.200.49.158'
REMOTE_CONFIG='/usr/local/etc/raksmart-hy2/server.yaml'
STATE='/var/lib/vps-panel/state.private.json'


def access_module():
    path=helpers.FOLDER.parent/'raksmart-198.200.49.158'/'ssh_access.py'
    spec=importlib.util.spec_from_file_location('alternate_158_ssh',path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def private_read(sftp,path):
    with sftp.open(path,'rb') as stream:return stream.read()


def run(args):
    report_path=helpers.FOLDER/args.report
    directory=base.TEMP_ROOT/secrets.token_hex(8)
    ssh,sftp,client=None,None,None
    ssh63,sftp63,client63=None,None,None
    own_download_processes=[]
    report={'success':False,'started_at':base.utc(),'server':HOST,'configuration_changes':0,
            'exit_changes':0,'credential_changes':0,'cleanup_errors':[]}
    started=time.monotonic()
    stage='offline-gate'
    try:
        helpers.require(not base.TEMP_ROOT.is_symlink(),'Unsafe private parent')
        report['private_directory_acl']=base.make_private(directory)
        report['script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if args.check_local:
            node=helpers.synthetic_nodes()[0]
            node['server']=HOST
            client=base.BenchClient(directory/'synthetic',node,started)
            client.syntax()
            report.update(success=True,offline_check=True,server_requests=0)
            return report
        helpers.require(not report_path.exists(),'Preserve existing report; use a distinct report name')
        targets=None
        if args.fast_pair:
            stage='fresh-fast-target-discovery'
            targets,report['discovery']=fast.discover()
            for target in targets:fast.bounded_url(target['url'])
            stage='current-63-identity'
            ssh63=helpers.connect()
            sftp63=ssh63.open_sftp()
            sftp63.get_channel().settimeout(20)
            accounts63,store63=helpers.collect_accounts(sftp63)
            account63=next(item for item in accounts63 if item['id']=='admin')
            helpers.require(account63['expected_ip']==base.live.IP,'Current .63 AUTO server exit required')
        stage='live-private-identity'
        access=access_module()
        ssh=access.connect()
        sftp=ssh.open_sftp()
        sftp.get_channel().settimeout(20)
        config_raw=private_read(sftp,REMOTE_CONFIG)
        state_raw=private_read(sftp,STATE)
        config=yaml.safe_load(config_raw)
        helpers.require(config.get('listen')=='0.0.0.0:443' and config.get('auth',{}).get('type')=='password',
                        'Current .158 HY2 is not expected independent password entrance')
        helpers.require(len(config.get('outbounds',[]))==1 and config['outbounds'][0].get('type')=='direct',
                        'Current .158 HY2 outbound is not direct')
        cert_path=config.get('tls',{}).get('cert')
        helpers.require(isinstance(cert_path,str) and cert_path.startswith('/usr/local/etc/raksmart-hy2/')
                        and cert_path.endswith('.pem'),'Unexpected .158 certificate location')
        cert_raw=private_read(sftp,cert_path)
        fingerprint=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert_raw.decode())).hexdigest()
        node={'name':'ALTERNATE-158-HY2','type':'hysteria2','server':HOST,'port':443,
              'password':config['auth']['password'],'sni':'raksmart-hy2.local','skip-cert-verify':False,
              'fingerprint':fingerprint,'udp':False,'bbr-profile':'standard'}
        report.update(hy2_config_sha256=hashlib.sha256(config_raw).hexdigest(),
                      current_state_sha256=hashlib.sha256(state_raw).hexdigest(),
                      physical_interface='WLAN',tls_verification=True,
                      method={'destination':'speed.cloudflare.com','payload_bytes':8388608,
                              'maximum_seconds':12,'streams':1,'first_request_is_identity_warmup':True,
                              'normal_existing_hy2_server_direct':True})
        epoch_command="systemctl show raksmart-hy2.service --property=MainPID --property=ExecMainStartTimestampMonotonic"
        code,epoch_before,_=access.execute(ssh,epoch_command,timeout=8)
        helpers.require(code==0,'Current .158 HY2 process epoch unavailable')
        stage='isolated-client'
        client=base.BenchClient(directory/'alternate',node,started)
        client.start(time.monotonic()+35)
        stage='identity'
        identity=client.request('light',HOST,max_time=10)
        report['identity']=identity
        helpers.require(identity['success'],'Existing .158 HY2 did not verify its server public exit')
        if args.fast_pair:
            report['method']={'destination':'same freshly signed Fast official targets',
                'maximum_payload_per_path':67108864,'maximum_seconds_per_path':12,'parallel_requests':4,
                'paths_order':[HOST,base.live.IP],'strictly_sequential':True,'same_signed_urls':True,
                'physical_interface':'WLAN','normal_hy2_nodes':'existing .158 direct and .63 AUTO bridge',
                'architecture_limit':'.158 HY2 direct and .63 HY2 Xray bridge are existing different deployments'}
            stage='alternate-158-fast-download'
            report['paths']=[fast.path_measurement('existing-158-hy2',client.proxy_port,targets,own_download_processes)]
            client.close()
            stage='current-63-fast-download'
            client63=base.BenchClient(directory/'current63',account63['nodes']['hy2'],started)
            client63.start(time.monotonic()+35)
            report['identity63']=client63.request('light',base.live.IP,max_time=10)
            helpers.require(report['identity63']['success'],'Current .63 HY2 server exit failed identity check')
            native_before=helpers.native_snapshot(ssh63,account63,'hy2')
            report['paths'].append(fast.path_measurement('current-63-hy2',client63.proxy_port,targets,own_download_processes))
            native_after=helpers.native_snapshot(ssh63,account63,'hy2')
            report['paths'][-1]['native_hy2_account_counter_delta']=helpers.counter_delta(native_before,native_after)
            after_store63=helpers.ledger(sftp63)
            registry63=helpers.private_json(sftp63,helpers.OWNER+'/users.private.json')
            records63={'admin':account63['record'],**{a['id']:a for a in registry63['users']}}
            report['all_63_account_settings_preserved']=all(helpers.settings_hash(
                helpers.private_json(sftp63,a['state_path']),records63[a['id']],after_store63)==a['settings_hash']
                for a in accounts63)
            measured_success=all(p['success'] for p in report['paths']) and report['all_63_account_settings_preserved']
        else:
            stage='bounded-download'
            base.emit('phase-start',stage,server=HOST,maximum_payload_bytes=8388608,maximum_seconds=12)
            measured=client.request('download',HOST,size=8388608,max_time=12)
            measured['bounded_partial']=measured['curl_exit_code']==28 and measured['actual_download_bytes']>0 and measured['http_code']==200
            report['download']=measured
            measured_success=measured['success'] or measured['bounded_partial']
        stage='protected-preservation'
        report['current_state_preserved']=private_read(sftp,STATE)==state_raw
        report['hy2_config_preserved']=private_read(sftp,REMOTE_CONFIG)==config_raw
        report['certificate_preserved']=private_read(sftp,cert_path)==cert_raw
        code,epoch_after,_=access.execute(ssh,epoch_command,timeout=8)
        report['158_hy2_epoch_unchanged']=code==0 and epoch_after==epoch_before
        report['success']=measured_success and report['158_hy2_epoch_unchanged'] and all(report[key]
                          for key in ('current_state_preserved','hy2_config_preserved','certificate_preserved'))
        base.emit('phase-end','alternate-158',success=report['success'])
        return report
    except Exception as error:
        report.update(failure_stage=stage,error_type=type(error).__name__)
        return report
    finally:
        for process in own_download_processes:
            if process.poll() is None:
                process.kill();process.communicate(timeout=4)
        if client63 is not None:
            try:client63.close()
            except Exception as error:report['cleanup_errors'].append(type(error).__name__)
        if client is not None:
            try:client.close()
            except Exception as error:report['cleanup_errors'].append(type(error).__name__)
        if sftp is not None:sftp.close()
        if ssh is not None:ssh.close()
        if sftp63 is not None:sftp63.close()
        if ssh63 is not None:ssh63.close()
        try:
            helpers.require(directory.resolve().parent==base.TEMP_ROOT.resolve() and not directory.is_symlink()
                            and re.fullmatch(r'[a-f0-9]{16}',directory.name),'Unsafe cleanup path')
            if directory.exists():shutil.rmtree(str(directory))
        except Exception as error:report['cleanup_errors'].append(type(error).__name__)
        report['own_client_terminated']=client is None or client.process is None or client.process.poll() is not None
        report['own_curl_processes_terminated']=client is None or all(p.poll() is not None for p in client.all_children)
        report['own_secondary_client_terminated']=client63 is None or client63.process is None or client63.process.poll() is not None
        report['own_fast_download_processes_terminated']=all(p.poll() is not None for p in own_download_processes)
        report['temporary_private_files_removed']=not directory.exists()
        if report['cleanup_errors'] or not all(report[key] for key in
                ('own_client_terminated','own_curl_processes_terminated','own_secondary_client_terminated',
                 'own_fast_download_processes_terminated','temporary_private_files_removed')):
            report['success']=False
        report['finished_at']=base.utc()
        if args.run and not report_path.exists():report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run',action='store_true')
    group.add_argument('--check-local',action='store_true')
    parser.add_argument('--fast-pair',action='store_true')
    parser.add_argument('--report',default='alternate-158-cloudflare-current.json',type=lambda value:value
                        if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}\.json',value) else parser.error('Safe JSON basename required'))
    result=run(parser.parse_args())
    print(json.dumps(result),flush=True)
    raise SystemExit(0 if result.get('success') else 1)
