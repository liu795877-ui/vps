"""Narrow temporary admin443 client-bandwidth permission trial.

Only ignoreClientBandwidth may change. Original bytes/attributes are kept in
a private checkpoint. Traffic is sampled before restart and never restored
from a checkpoint. Existing maintenance modules stay unchanged.
"""
import argparse
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import optimize_udp_buffers_remote as m
import tune_hy2_profile_remote as lifecycle

FORMAT='vps-hy2-client-bandwidth-trial-v1'
PORT=443
PREFIX='vps-hy2-bandwidth-20261011-'


def config(data):
    value=lifecycle.config(data)
    m.require(type(value.get('ignoreClientBandwidth')) is bool,'Explicit boolean client-bandwidth policy required')
    return value


def unchanged(value):
    result=copy.deepcopy(value)
    result.pop('ignoreClientBandwidth')
    return result


def checkpoint(value,create):
    path=Path(value)
    m.require(path.is_absolute() and path.parent==Path('/root') and not path.is_symlink()
              and re.fullmatch(PREFIX+r'[A-Za-z0-9-]{1,80}',path.name),'Invalid private bandwidth checkpoint')
    if create:
        m.require(not path.exists(),'Checkpoint already exists')
        path.mkdir(mode=0o700)
    m.require(path.is_dir() and path.stat().st_uid==0 and stat.S_IMODE(path.stat().st_mode)==0o700,
              'Private checkpoint permissions differ')
    return path


def change(context,journal,backup,action,data,info):
    path=m.safe_file(lifecycle.config_path(PORT))
    before_data,before_info=path.read_bytes(),m.attributes(path)
    before_sha,after_sha=m.sha(path),hashlib.sha256(data).hexdigest()
    baseline=m.identity(context)
    lifecycle.protected(journal['identity'],baseline,PORT,journal['expected_sha256'],True)
    m.require(before_sha==journal['expected_sha256'],'Concurrent runtime change prevents trial')
    record=next(item for item in baseline['records'] if item['port']==PORT)
    lifecycle.official(record)
    m.require(unchanged(config(before_data))==unchanged(config(data)),'Trial would change a non-policy field')
    before_ledger=m.ledger(context)
    if before_data==data:
        m.require(action=='restore' and config(data)['ignoreClientBandwidth'] is True,
                  'Only original restore may be an unchanged operation')
        return {'success':True,'action':action,'port':PORT,'already_restored':True,
                'ignore_client_bandwidth':True,'runtime_sha256':before_sha,
                'traffic_ledger_restored':False,'ledger_totals_non_decreasing':True,'panel_ready':True}
    objects,attempted=None,False
    try:
        m.run(['systemctl','stop',m.PANEL])
        lifecycle.protected(baseline,m.identity(context),PORT,before_sha,False)
        objects=m.traffic_context(context)
        accounts,integration,traffic=objects
        canonical=integration.config(accounts._record('admin'))
        m.require(unchanged(config(before_data))==unchanged(canonical),'Runtime differs from canonical non-policy fields')
        lifecycle.protected(baseline,m.identity(context),PORT,before_sha,False)
        journal['pending_sha256']=after_sha
        m.private_json(backup/'checkpoint.private.json',journal)
        final=m.prepare_restart(accounts,integration,traffic,record)
        m.require(m.sha(path)==before_sha,'Concurrent runtime change before application')
        attempted=True
        m.atomic(path,data,info)
        restart=lifecycle.synchronize(accounts,integration,traffic,record,final)
        lifecycle.official(record)
        lifecycle.protected(baseline,m.identity(context),PORT,after_sha,False)
        m.check_ledger(before_ledger,m.ledger(context))
        m.run(['systemctl','start',m.PANEL])
        m.wait_panel(context)
        lifecycle.protected(baseline,m.identity(context),PORT,after_sha,True)
        m.check_ledger(before_ledger,m.ledger(context))
        journal.update(expected_sha256=after_sha,pending_sha256=None)
        m.private_json(backup/'checkpoint.private.json',journal)
        return {'success':True,'action':action,'port':PORT,'ignore_client_bandwidth':config(data)['ignoreClientBandwidth'],
            'runtime_sha256':after_sha,'original_runtime_sha256':journal['original']['sha256'],
            'only_runtime_boolean_changed':True,'accounts_auth_exit_rules_profiles_preserved':True,
            'other_proxy_epochs_preserved':True,'ledger_totals_non_decreasing':True,
            'traffic_ledger_restored':False,'limits_preserved':True,'restart':restart,
            'private_checkpoint':str(backup),'panel_ready':True,
            'panel_session_notice':'Panel sessions require login again after worker restart.'}
    except BaseException as error:
        result={'success':False,'action':action,'port':PORT,'error_type':type(error).__name__}
        try:
            if m.active(m.service(m.PANEL)):m.run(['systemctl','stop',m.PANEL])
            objects=objects or m.traffic_context(context)
            accounts,integration,traffic=objects
            traffic.reload()
            m.require(m.sha(path) in (before_sha,after_sha),'Concurrent change prevents rollback')
            if attempted:
                final=None
                if m.active(m.service(record['hy2'])):
                    try:final=m.prepare_restart(accounts,integration,traffic,record)
                    except Exception:pass
                m.atomic(path,before_data,before_info)
                if final:lifecycle.synchronize(accounts,integration,traffic,record,final)
                else:
                    m.run(['systemctl','restart',record['hy2']])
                    m.wait_hy2(integration,accounts._record('admin'))
                    m.sample(traffic,'admin')
            m.check_ledger(before_ledger,m.ledger(context))
            journal.update(expected_sha256=before_sha,pending_sha256=None)
            m.private_json(backup/'checkpoint.private.json',journal)
            result['rollback']={'success':True,'runtime_sha256':before_sha,'traffic_ledger_restored':False,
                                'ledger_totals_non_decreasing':True}
        except BaseException:
            result['rollback']={'success':False,'failure':'Host inspection required'}
        finally:
            try:
                m.run(['systemctl','start',m.PANEL]);m.wait_panel(context)
                lifecycle.protected(baseline,m.identity(context),PORT,before_sha,True)
                result['panel_ready']=True
                result['rollback_identity_preserved']=True
            except Exception:result['panel_ready']=False
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action',required=True,choices=('snapshot','set','restore'))
    parser.add_argument('--package-root',required=True)
    parser.add_argument('--backup-dir')
    args=parser.parse_args()
    m.require(os.name=='posix' and os.geteuid()==0,'Root Linux process required')
    context=m.launch_context(Path(args.package_root));m.import_package(context)
    baseline=m.identity(context)
    record=next(item for item in baseline['records'] if item['port']==PORT)
    lifecycle.official(record)
    path=m.safe_file(lifecycle.config_path(PORT));current=config(path.read_bytes())
    if args.action=='snapshot':
        return {'success':True,'action':'snapshot','port':PORT,'ignore_client_bandwidth':current['ignoreClientBandwidth'],
            'runtime_sha256':m.sha(path),'source_sha256':m.sha(Path(context['package_root'])/'panel/hy2.py'),
            'binary_sha256':m.sha('/usr/local/bin/raksmart-hysteria2'),
            'protected_identity_sha256':m.digest_json(baseline),
            'ledger_limits_months_sha256':m.digest_json(m.ledger(context)),'runtime':m.runtime_snapshot(context)}
    m.require(args.backup_dir,'Private checkpoint required')
    m.require(not m.LOCK.is_symlink() and m.LOCK.parent.is_dir(),'Unsafe maintenance lock')
    fd=os.open(str(m.LOCK),os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        backup=checkpoint(args.backup_dir,args.action=='set' and not Path(args.backup_dir).exists())
        journal_path=backup/'checkpoint.private.json'
        if journal_path.exists():
            m.safe_file(journal_path)
            m.require(journal_path.stat().st_uid==0 and stat.S_IMODE(journal_path.stat().st_mode)==0o600,
                      'Checkpoint file permissions differ')
            journal=json.loads(journal_path.read_text())
            m.require(journal.get('format')==FORMAT and journal.get('context')==context and journal.get('port')==PORT,
                      'Checkpoint differs from adopted target')
            m.require(journal.get('pending_sha256') is None,'Interrupted maintenance requires inspection')
        else:
            m.require(args.action=='set' and current['ignoreClientBandwidth'] is True,
                      'Trial requires explicit original true policy')
            journal={'format':FORMAT,'context':context,'port':PORT,'identity':baseline,
                'original':lifecycle.private_bytes(path.read_bytes(),m.attributes(path)),
                'expected_sha256':m.sha(path),'pending_sha256':None}
            m.private_json(journal_path,journal)
        lifecycle.protected(journal['identity'],m.identity(context),PORT,journal['expected_sha256'],True)
        if args.action=='restore':
            data=base64.b64decode(journal['original']['data'],validate=True)
            m.require(hashlib.sha256(data).hexdigest()==journal['original']['sha256'],'Original private bytes differ')
            m.require(config(data)['ignoreClientBandwidth'] is True,'Original policy is not true')
            info=journal['original']['attributes']
        else:
            current['ignoreClientBandwidth']=False
            data=(json.dumps(current,sort_keys=True,indent=2)+'\n').encode()
            info=m.attributes(path)
        return change(context,journal,backup,args.action,data,info)
    finally:os.close(fd)


if __name__=='__main__':
    try:result=main()
    except BaseException as error:result={'success':False,'error_type':type(error).__name__}
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if result.get('success') else 1)
