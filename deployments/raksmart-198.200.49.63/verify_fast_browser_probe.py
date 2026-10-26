"""Explicit real FAST browser run bracketed by read-only six native counters.

No local client or server changes. Signed URLs/tokens never enter reports.
Run one mode at a time; fresh Edge uses explicit HTTP proxy or current OS/TUN.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

import benchmark_hy2_latency as base
import verify_hy2_clients as helpers


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true',required=True)
    parser.add_argument('--mode',choices=('http-proxy','tun'),required=True)
    parser.add_argument('--label',required=True)
    parser.add_argument('--max-mib',type=int,choices=(256,1024),default=256)
    args=parser.parse_args()
    import re
    helpers.require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',args.label), 'Use a simple lowercase label')
    folder=helpers.FOLDER
    browser_report=folder/('fast-browser-'+args.label+'.json')
    report_path=folder/('fast-browser-'+args.label+'-verified.json')
    helpers.require(not browser_report.exists() and not report_path.exists(),'Reports already exist')
    report={'success':False,'label':args.label,'mode':args.mode,'started_at':base.utc(),
        'configuration_changes':0,'credential_changes':0,'exit_changes':0,
        'signed_urls_saved':False,'tokens_saved':False,'native_scope':'All account traffic during browser run, including unrelated activity.',
        'cleanup_errors':[],
        'browser_maximum_bytes':args.max_mib*1024*1024,
        'browser_byte_limit_scope':'CDP soft byte limit with 16 MiB early stop margin; quota gate reserves an additional 64 MiB.',
        'script_sha256':hashlib.sha256((folder/'fast_browser_probe.mjs').read_bytes()).hexdigest()}
    ssh=sftp=process=None;phase='server-baseline'
    try:
        ssh=helpers.connect();sftp=ssh.open_sftp();sftp.get_channel().settimeout(20)
        accounts,before_store=helpers.collect_accounts(sftp)
        month=time.strftime('%Y-%m',time.gmtime())
        admin=next(item for item in accounts if item['id']=='admin')
        limits=before_store['users']['admin'];used=sum(helpers.month_totals(before_store,'admin',month).values())
        helpers.require(not limits.get('quota_bytes') or limits['quota_bytes']-used>(args.max_mib+64)*1024*1024,
                        'Quota remaining is insufficient for bounded browser run')
        before={(item['port'],source):helpers.native_snapshot(ssh,item,source) for item in accounts for source in ('hy2','xray')}
        phase='fresh-browser-official-fast'
        process=subprocess.Popen(['node',str(folder/'fast_browser_probe.mjs'),'--mode',args.mode,'--label',args.label,'--max-mib',str(args.max_mib)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=base.live.NO_WINDOW)
        # On a bounded timeout, terminate only this fresh node/browser tree.
        try:
            unused_output,unused_error=process.communicate(timeout=170)
        except subprocess.TimeoutExpired:
            subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=12,creationflags=base.live.NO_WINDOW)
            process.communicate(timeout=8)
            raise
        report['browser_exit_code']=process.returncode
        helpers.require(browser_report.is_file(),'Browser did not produce a sanitized report')
        report['browser']=json.loads(browser_report.read_text(encoding='utf-8'))
        phase='read-only-native-after'
        after={(item['port'],source):helpers.native_snapshot(ssh,item,source) for item in accounts for source in ('hy2','xray')}
        report['native_account_counter_delta']=[{'port':port,'protocol':source,
            **helpers.counter_delta(before[(port,source)],after[(port,source)])} for port,source in before]
        current,current_store=helpers.collect_accounts(sftp)
        report['all_account_settings_preserved']={item['port']:item['settings_hash'] for item in accounts}=={item['port']:item['settings_hash'] for item in current}
        helpers.require(month==time.strftime('%Y-%m',time.gmtime()),'Run crossed billing month')
        report['monthly_totals_non_decreasing']=all(all(helpers.month_totals(current_store,item['id'],month)[key]>=amount
            for key,amount in helpers.month_totals(before_store,item['id'],month).items()) for item in accounts)
        report['success']=bool(report['browser'].get('success') and report['all_account_settings_preserved'] and report['monthly_totals_non_decreasing'])
    except Exception as error:
        report.update(failure_phase=phase,error_type=type(error).__name__)
    finally:
        if process is not None and process.poll() is None:
            try:
                subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,timeout=12,creationflags=base.live.NO_WINDOW)
                process.communicate(timeout=8)
            except BaseException as error:
                report['cleanup_errors'].append('own-browser-tree:'+type(error).__name__)
        for name,resource in [('sftp',sftp),('ssh',ssh)]:
            if resource is not None:
                try:resource.close()
                except BaseException as error:report['cleanup_errors'].append(name+':'+type(error).__name__)
        report['own_node_process_terminated']=process is None or process.poll() is not None
        report['success']=bool(report['success'] and report['own_node_process_terminated'] and not report['cleanup_errors'])
        report['finished_at']=base.utc()
        with report_path.open('x',encoding='utf-8') as stream:stream.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'success':report['success'],'report':str(report_path),
        'partial':report.get('browser',{}).get('partial'),'visible_result':report.get('browser',{}).get('visible_result')}))
    return report


if __name__=='__main__':
    result=main()
    raise SystemExit(0 if result.get('success') else 1)
