"""End-to-end BBR -> isolated download Brutal -> original BBR comparison.

No production source, active-client profile, credentials, exits or limits change.
One temporary server admin443 boolean enables that fresh isolated client's
download request; original raw runtime bytes are restored in finally. No traffic
ledger is backed up/restored. If this local process/host is forcibly terminated,
root must use the retained private checkpoint with --restore-only.
"""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import time

import yaml
import benchmark_hy2_latency as base
import benchmark_fast_regression as fast
import verify_hy2_clients as helpers


HELPER='tune_hy2_client_bandwidth_remote.py'
DEPENDENCIES=(HELPER,'tune_hy2_profile_remote.py','optimize_udp_buffers_remote.py')
LOG_PROGRAM=r'''
import json,subprocess,sys,time
started=float(sys.argv[1])
p=subprocess.run(['journalctl','-u','raksmart-hy2@443.service','--since','@'+str(started),
    '--no-pager','-o','json','-n','100'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=7)
out=[]
for line in p.stdout.decode('utf-8','replace').splitlines():
    try:item=json.loads(line)
    except ValueError:continue
    if not isinstance(item,dict):continue
    text=item.get('MESSAGE','')
    if isinstance(text,list) and all(type(v)is int and 0<=v<=255 for v in text):text=bytes(text).decode('utf-8','replace')
    if not isinstance(text,str) or 'client connected' not in text.lower():continue
    try:data=json.loads(text[text.index('{'):])
    except ValueError:continue
    if not isinstance(data,dict):continue
    tx=data.get('tx')
    if type(tx)is int and tx>=0:out.append({'server_download_tx_bytes_per_second':tx})
print(json.dumps({'journal_available':p.returncode==0,'connections':out,
                 'scope':'All admin443 client-connected events since this phase start; no raw message or auth retained.'}))
'''


def candidate_node(original):
    value=copy.deepcopy(original)
    helpers.require('up' not in value and 'down' not in value,'Trial requires original absent up/down fields')
    value['down']='50 Mbps'
    return value


def upload_tools(ssh,sftp,remote_dir):
    helpers.require(re.fullmatch(r'/root/vps-hy2-bandwidth-tools-20261011-[a-f0-9]{16}',remote_dir),'Unsafe remote tool path')
    sftp.mkdir(remote_dir,mode=0o700)
    info=sftp.lstat(remote_dir)
    helpers.require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,
                    'Remote tool directory owner/permissions differ')
    hashes={}
    for name in DEPENDENCIES:
        data=(helpers.FOLDER/name).read_bytes()
        ast.parse(data.decode(),feature_version=(3,6))
        path=remote_dir+'/'+name
        with sftp.open(path,'wb') as stream:stream.write(data)
        sftp.chmod(path,0o600)
        with sftp.open(path,'rb') as stream:actual=stream.read()
        helpers.require(actual==data,'Uploaded helper source differs')
        hashes[name]=hashlib.sha256(data).hexdigest()
    return hashes


def remote_action(ssh,tools,backup,action):
    argv=['python3',tools+'/'+HELPER,'--action',action,'--package-root','/opt/vps-panel']
    if action!='snapshot':argv+=['--backup-dir',backup]
    code,output,_=helpers.execute(ssh,' '.join(shlex.quote(value) for value in argv),timeout=150)
    result=json.loads(output)
    helpers.require(isinstance(result,dict),'Remote maintenance did not return structured result')
    result['remote_exit_code']=code
    return result


def phase(ssh,account,node,targets,directory,label,clock_start,own_clients,own_processes):
    client=base.BenchClient(directory/label,node,clock_start)
    own_clients.append(client)
    client.start(time.monotonic()+35)
    log_start=time.time()-1
    identity=client.request('light',base.live.IP,max_time=10)
    helpers.require(identity['success'],'Current admin server exit identity failed')
    native_before=helpers.native_snapshot(ssh,account,'hy2')
    result=fast.path_measurement(label,client.proxy_port,targets,own_processes)
    native_after=helpers.native_snapshot(ssh,account,'hy2')
    result['identity']=identity
    result['native_hy2_account_counter_delta']=helpers.counter_delta(native_before,native_after)
    code,out,_=helpers.execute(ssh,'python3 -c '+shlex.quote(LOG_PROGRAM)+' '+str(log_start),timeout=12)
    helpers.require(code==0,'Sanitized negotiation evidence unavailable')
    result['server_negotiation']=json.loads(out)
    result['client_download_bandwidth']=node.get('down')
    result['client_upload_bandwidth_present']='up' in node
    client.close()
    return result


def cleanup_processes_and_restore(report,clients,processes,trial_attempted,restored,ssh,tools,backup,restore_action=None):
    """Cleanup failures must never bypass the production rollback attempt."""
    try:
        for process in processes:
            try:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=4)
            except BaseException as error:
                report['cleanup_errors'].append('curl:'+type(error).__name__)
        for client in reversed(clients):
            try:
                client.close()
            except BaseException as error:
                report['cleanup_errors'].append('client:'+type(error).__name__)
    finally:
        if trial_attempted and not restored and ssh is not None:
            try:
                action=restore_action or remote_action
                report['finally_restore']=action(ssh,tools,backup,'restore')
                restored=report['finally_restore'].get('success') is True
            except BaseException as error:
                report['finally_restore']={'success':False,'error_type':type(error).__name__}
        report['trial_original_policy_restored']=not trial_attempted or restored
    return restored


def check_cleanup_rollback_fixture():
    class FailedKill:
        def poll(self):return None
        def kill(self):raise OSError('synthetic cleanup failure')
    class FailedWait:
        def poll(self):return None
        def kill(self):pass
        def communicate(self,timeout):raise subprocess.TimeoutExpired('synthetic-only',timeout)
    class FailedClient:
        def close(self):raise OSError('synthetic client cleanup failure')
    calls=[]
    def restore_spy(ssh,tools,backup,action):
        calls.append(action)
        return {'success':True,'offline_fixture':True}
    report={'cleanup_errors':[]}
    restored=cleanup_processes_and_restore(report,[FailedClient()],[FailedKill(),FailedWait()],
                                          True,False,object(),'synthetic-tools','synthetic-backup',restore_spy)
    helpers.require(restored and calls==['restore'] and report['trial_original_policy_restored']
                    and report['cleanup_errors']==['curl:OSError','curl:TimeoutExpired','client:OSError'],
                    'Injected process/client cleanup failure skipped mandatory production restore')
    return {'injected_kill_oserror':True,'injected_communicate_timeout':True,'injected_client_close_oserror':True,
            'restore_invoked_exactly_once':True,'network_requests':0}


def offline_check(directory):
    for name in DEPENDENCIES:ast.parse((helpers.FOLDER/name).read_text(),feature_version=(3,6))
    ast.parse(LOG_PROGRAM,feature_version=(3,6))
    original=helpers.synthetic_nodes()[0]
    brutal=candidate_node(original)
    stripped=copy.deepcopy(brutal);stripped.pop('down')
    helpers.require(stripped==original and 'up' not in brutal,'Only candidate download bandwidth may change')
    nodes=[original,brutal]
    checks=[]
    for index,node in enumerate(nodes):
        client=base.BenchClient(directory/('syntax-'+str(index)),node,time.monotonic())
        try:client.syntax();checks.append(True)
        finally:client.close()
    tree=ast.parse((helpers.FOLDER/HELPER).read_text())
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='unchanged')
    namespace={'copy':copy}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'<narrow-policy-fixture>','exec'),namespace)
    a={'ignoreClientBandwidth':True,'congestion':{'type':'bbr','bbrProfile':'standard'},'auth':{'password':'synthetic'}}
    b=copy.deepcopy(a);b['ignoreClientBandwidth']=False
    helpers.require(namespace['unchanged'](a)==namespace['unchanged'](b),'Single boolean policy scope fixture failed')
    b['auth']['password']='changed'
    helpers.require(namespace['unchanged'](a)!=namespace['unchanged'](b),'Credential protection fixture failed')
    return {'official_mihomo_bbr_and_download_50mbps_syntax':all(checks),
            'only_down_added_upload_field_absent':True,'single_boolean_scope_fixture_passed':True,
            'remote_python36_syntax_passed':True,'cleanup_failure_rollback_fixture':check_cleanup_rollback_fixture(),
            'server_requests':0}


def run(args):
    report_path=helpers.FOLDER/args.report
    directory=base.TEMP_ROOT/secrets.token_hex(8)
    task_id=secrets.token_hex(8)
    tools=args.tools or '/root/vps-hy2-bandwidth-tools-20261011-'+task_id
    backup=args.backup_dir or '/root/vps-hy2-bandwidth-20261011-'+task_id
    ssh,sftp=None,None
    own_clients,own_processes=[],[]
    trial_attempted,restored=False,False
    report={'success':False,'started_at':base.utc(),'production_source_changes':0,'active_client_changes':0,
            'credential_changes':0,'exit_changes':0,'traffic_ledger_restored':False,'phases':[],
            'cleanup_errors':[],'temporary_remote_tools':tools,'private_checkpoint':backup,
            'rollback_limit':'try/finally restores on ordinary failure; forcibly killing this process or host requires --restore-only using private checkpoint.'}
    started=time.monotonic()
    stage='local-gate'
    try:
        helpers.require(not base.TEMP_ROOT.is_symlink(),'Unsafe private parent')
        report['private_directory_acl']=base.make_private(directory)
        report['script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['source_hashes']={name:hashlib.sha256((helpers.FOLDER/name).read_bytes()).hexdigest() for name in DEPENDENCIES}
        if args.check_local:
            report['offline']=offline_check(directory)
            report['success']=True
            return report
        helpers.require(not report_path.exists(),'Preserve existing report with a distinct filename')
        ssh=helpers.connect();sftp=ssh.open_sftp();sftp.get_channel().settimeout(20)
        if args.restore_only:
            helpers.require(args.backup_dir and args.tools,'Existing tools and checkpoint required for restore-only')
            report['restore']=remote_action(ssh,tools,backup,'restore')
            restored=report['restore'].get('success') is True
            report['success']=restored
            return report
        stage='private-current-profile'
        accounts,before_store=helpers.collect_accounts(sftp)
        account=next(item for item in accounts if item['id']=='admin')
        helpers.require(account['expected_ip']==base.live.IP,'Current admin AUTO server exit required')
        original=copy.deepcopy(account['nodes']['hy2'])
        candidate=candidate_node(original)
        quota=before_store.get('users',{}).get('admin',{}).get('quota_bytes',0)
        month=time.strftime('%Y-%m',time.gmtime())
        used=sum(helpers.month_totals(before_store,'admin',month).values())
        helpers.require(not quota or quota-used>3*67108864+16777216,'Normal remaining quota insufficient')
        report['original_hy2_node_sha256']=helpers.fingerprint(original)
        report['candidate_node_sha256']=helpers.fingerprint(candidate)
        report['profile_sha256']=account['profile_sha256']
        stage='reviewed-maintenance-tools'
        report['uploaded_tool_hashes']=upload_tools(ssh,sftp,tools)
        stage='server-snapshot'
        report['snapshot_before']=remote_action(ssh,tools,backup,'snapshot')
        helpers.require(report['snapshot_before'].get('success') and report['snapshot_before'].get('ignore_client_bandwidth') is True,
                        'Original server policy is not expected true')
        stage='fresh-fast-targets'
        targets,report['discovery']=fast.discover()
        for target in targets:fast.bounded_url(target['url'])
        report['method']={'signed_targets_fetched_once_kept_in_memory':True,'phases':['bbr-before','brutal-down50','bbr-after'],
            'strictly_sequential':True,'maximum_payload_per_phase':67108864,'maximum_seconds_per_phase':12,
            'only_candidate_client_down_added':'50 Mbps','candidate_client_up_present':False,
            'loss_compensation_setting_added':False,'only_admin_server_ignoreClientBandwidth_temporarily_false':True,
            'original_server_bytes_restored':True,'user_client_profile_unchanged':True,
            'server_restart_effect':'Only admin HY2 restarted twice; panel worker paused/restarted to protect ledger writer.'}
        stage='bbr-before'
        report['phases'].append(phase(ssh,account,original,targets,directory,stage,started,own_clients,own_processes))
        stage='allow-client-download-bandwidth'
        trial_attempted=True
        report['apply']=remote_action(ssh,tools,backup,'set')
        helpers.require(report['apply'].get('success'),'Trial server flag application failed')
        stage='brutal-down50'
        report['phases'].append(phase(ssh,account,candidate,targets,directory,stage,started,own_clients,own_processes))
        expected_tx=6250000
        negotiated=report['phases'][-1]['server_negotiation'].get('connections',[])
        report['candidate_brutal_tx_negotiation_verified']=any(row.get('server_download_tx_bytes_per_second')==expected_tx for row in negotiated)
        stage='restore-original-runtime'
        report['restore']=remote_action(ssh,tools,backup,'restore')
        restored=report['restore'].get('success') is True
        helpers.require(restored,'Original runtime restore did not complete')
        stage='bbr-after'
        report['phases'].append(phase(ssh,account,original,targets,directory,stage,started,own_clients,own_processes))
        stage='final-preservation'
        report['snapshot_after']=remote_action(ssh,tools,backup,'snapshot')
        report['original_runtime_bytes_restored']=(report['snapshot_before']['runtime_sha256']==report['snapshot_after']['runtime_sha256']
                                                   and report['snapshot_after'].get('ignore_client_bandwidth') is True)
        after_store=helpers.ledger(sftp)
        registry=helpers.private_json(sftp,helpers.OWNER+'/users.private.json')
        records={'admin':account['record'],**{a['id']:a for a in registry['users']}}
        report['all_account_settings_preserved']=all(helpers.settings_hash(helpers.private_json(sftp,a['state_path']),
            records[a['id']],after_store)==a['settings_hash'] for a in accounts)
        report['success']=(restored and report['original_runtime_bytes_restored'] and report['all_account_settings_preserved']
            and report['candidate_brutal_tx_negotiation_verified'] and all(row['success'] for row in report['phases']))
        return report
    except Exception as error:
        report.update(failure_stage=stage,error_type=type(error).__name__)
        if isinstance(error,fast.SafeFailure):report['safe_error_detail']=error.safe_detail
        return report
    finally:
        restored=cleanup_processes_and_restore(report,own_clients,own_processes,trial_attempted,restored,
                                              ssh,tools,backup)
        for name,resource in [('sftp',sftp),('ssh',ssh)]:
            if resource is not None:
                try:resource.close()
                except BaseException as error:report['cleanup_errors'].append(name+':'+type(error).__name__)
        try:
            helpers.require(directory.resolve().parent==base.TEMP_ROOT.resolve() and not directory.is_symlink()
                            and re.fullmatch(r'[a-f0-9]{16}',directory.name),'Unsafe cleanup path')
            if directory.exists():shutil.rmtree(str(directory))
        except Exception as error:report['cleanup_errors'].append(type(error).__name__)
        report['temporary_local_private_files_removed']=not directory.exists()
        try:
            report['own_processes_terminated']=all(c.process is None or c.process.poll() is not None for c in own_clients) and all(p.poll() is not None for p in own_processes)
        except BaseException as error:
            report['own_processes_terminated']=False
            report['cleanup_errors'].append('final-process-state:'+type(error).__name__)
        report['private_checkpoint_and_reviewed_remote_tools_retained']=not args.check_local
        if report['cleanup_errors'] or not report['trial_original_policy_restored'] or not report['temporary_local_private_files_removed'] or not report['own_processes_terminated']:
            report['success']=False
        report['finished_at']=base.utc()
        if not args.check_local and not report_path.exists():report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-local',action='store_true')
    group.add_argument('--run',action='store_true')
    group.add_argument('--restore-only',action='store_true')
    parser.add_argument('--report',default='hy2-client-bandwidth-trial.json',type=lambda value:value
                        if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}\.json',value) else parser.error('Safe JSON basename required'))
    parser.add_argument('--tools')
    parser.add_argument('--backup-dir')
    result=run(parser.parse_args())
    print(json.dumps(result),flush=True)
    raise SystemExit(0 if result.get('success') else 1)
