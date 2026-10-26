"""Bounded proxy throughput tests using a private Mihomo client bound to WLAN."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import socket
import statistics
import subprocess
import time
import yaml

FOLDER=Path(__file__).resolve().parent
parser=argparse.ArgumentParser()
parser.add_argument('--bytes',type=int,default=2000000)
parser.add_argument('--count',type=int,default=2)
parser.add_argument('--max-time',type=int,default=35)
parser.add_argument('--parallel',type=int,default=1)
parser.add_argument('--flclash',action='store_true')
parser.add_argument('--upload',action='store_true')
parser.add_argument('--label',default='')
parser.add_argument('--via-tokyo',action='store_true',
                    help='Route the isolated US client connection through the existing Tokyo node.')
parser.add_argument('--hysteria2',action='store_true',
                    help='Use the separate pinned-certificate HY2 trial profile over UDP.')
args=parser.parse_args()
if args.via_tokyo and args.flclash:
    parser.error('--via-tokyo requires an isolated client; it cannot change active FlClash')
if args.hysteria2 and (args.flclash or args.via_tokyo):
    parser.error('--hysteria2 requires its own isolated direct client')
report={'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
        'path':'Active FlClash' if args.flclash else 'Temporary Mihomo bound to physical WLAN',
        'direction':'upload' if args.upload else 'download',
        'parallel_streams':args.parallel,'requested_bytes_per_stream':args.bytes,'checks':[]}
if args.via_tokyo:
    report['path']='Temporary Mihomo bound to physical WLAN -> TOKYO-VPS -> RAKsmart-US'
if args.hysteria2:
    report['path']='Temporary Mihomo bound to physical WLAN -> RAKsmart-US-HY2 UDP443'
binary=Path('C:/Users/LENOVO/.cockpit_tools/proxy-engine/release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe')
folder=FOLDER/'speed-client'
folder.mkdir(exist_ok=True)
def port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1',0))
        return stream.getsockname()[1]
process=None
socks_port=7890
format='{"http_code":%{http_code},"size_download":%{size_download},"size_upload":%{size_upload},"time_total":%{time_total},"time_starttransfer":%{time_starttransfer},"time_appconnect":%{time_appconnect}}'
try:
    with (folder/'test.log').open('wb') as log:
        if not args.flclash:
            socks_port=port()
            source=(FOLDER/'hy2-draft'/'mihomo.private.yaml' if args.hysteria2 else
                    FOLDER/'raksmart-reality.private.yaml')
            profile=yaml.safe_load(source.read_text(encoding='utf-8'))
            if args.hysteria2:
                nodes=profile.get('proxies',[])
                if (len(nodes)!=1 or nodes[0].get('type')!='hysteria2' or
                    nodes[0].get('server')!='198.200.49.63' or nodes[0].get('port')!=443 or
                    nodes[0].get('skip-cert-verify') is not False or
                    not isinstance(nodes[0].get('fingerprint'),str) or
                    len(nodes[0]['fingerprint'].replace(':',''))!=64):
                    raise RuntimeError('HY2 profile is not the expected pinned-certificate US endpoint')
            profile.update({'mixed-port':socks_port,'mode':'rule','interface-name':'WLAN',
                            'unified-delay':True,'tcp-concurrent':True,'dns':{'enable':False},
                            'tun':{'enable':False},'log-level':'warning',
                            'rules':['MATCH,PROXY']})
            profile.pop('external-controller',None)
            if args.via_tokyo:
                previous=yaml.safe_load((FOLDER.parents[1]/'clash-reality.yaml').read_text(encoding='utf-8'))
                candidates=[node for node in previous.get('proxies',[]) if node.get('name')=='TOKYO-VPS']
                if len(candidates)!=1:
                    raise RuntimeError('Expected one TOKYO-VPS node in the existing local profile')
                tokyo=dict(candidates[0])
                if (tokyo.get('server'),tokyo.get('port'))!=('43.130.238.204',8443):
                    raise RuntimeError('Tokyo endpoint differs from the expected existing node')
                if tokyo.get('dialer-proxy'):
                    raise RuntimeError('Tokyo node already has a dialer; test chain would be ambiguous')
                us_candidates=[node for node in profile.get('proxies',[]) if node.get('name')=='RAKsmart-US']
                if len(us_candidates)!=1 or us_candidates[0].get('server')!='198.200.49.63':
                    raise RuntimeError('Expected one RAKsmart-US node with the deployed VPS address')
                if any(node.get('name')=='TOKYO-VPS' for node in profile.get('proxies',[])):
                    raise RuntimeError('Isolated profile already contains a TOKYO-VPS node')
                us_candidates[0]['dialer-proxy']='TOKYO-VPS'
                profile['proxies'].append(tokyo)
            config=folder/'mihomo-speed.private.yaml'
            config.write_text(yaml.safe_dump(profile,allow_unicode=True),encoding='utf-8')
            process=subprocess.Popen([str(binary),'-d',str(folder),'-f',str(config)],
                                     stdin=subprocess.DEVNULL,stdout=log,stderr=log,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            for _ in range(40):
                if process.poll() is not None:
                    raise RuntimeError('Temporary client exited; inspect private log')
                try:
                    with socket.create_connection(('127.0.0.1',socks_port),timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Temporary proxy listener did not start')
        prefix=['C:/Windows/System32/curl.exe','--proxy',f'socks5h://127.0.0.1:{socks_port}',
                '--noproxy','','--connect-timeout','10','--max-time',str(args.max_time),
                '--ssl-no-revoke','--silent','--show-error']
        report['identity_attempts']=[]
        for identity_attempt in range(1,2 if args.flclash else 4):
            try:
                identity=subprocess.run(prefix+['https://api.ipify.org'],capture_output=True,timeout=args.max_time+5)
                identity_output=identity.stdout
                identity_error=identity.stderr.decode('utf-8',errors='replace').strip()
                identity_code=identity.returncode
            except subprocess.TimeoutExpired as error:
                identity_output=error.stdout or b''
                identity_error='Identity request exceeded the process timeout'
                identity_code=28
            report['exit_ip']=identity_output.decode('utf-8',errors='replace').strip()
            report['identity_exit_code']=identity_code
            report['identity_error']=identity_error
            report['exit_matches_vps']=identity_code==0 and report['exit_ip']=='198.200.49.63'
            report['identity_attempts'].append({'attempt':identity_attempt,'exit_code':identity_code,
                                              'exit_ip':report['exit_ip'],'error':identity_error,
                                              'matches_vps':report['exit_matches_vps']})
            if report['exit_matches_vps'] or identity_code==0:
                break
            if identity_attempt<3 and not args.flclash:
                time.sleep(1)
        if not report['exit_matches_vps']:
            raise RuntimeError('Proxy egress verification failed; download not started')
        print('EXIT_VERIFIED',report['exit_ip'],flush=True)
        for sample in range(args.count):
            url=('https://speed.cloudflare.com/__up' if args.upload else
                 'https://speed.cloudflare.com/__down?bytes='+str(args.bytes))
            commands=[]
            for _ in range(args.parallel):
                command=prefix+['--output','NUL','--write-out',format]
                if args.upload:
                    command+=['--request','POST','--header','Content-Type: application/octet-stream',
                              '--header','Expect:','--data-binary','@-',url]
                else:
                    command+=[url]
                commands.append(command)
            import concurrent.futures
            started=time.perf_counter()
            def run(command):
                result=subprocess.run(command,input=b'\0'*args.bytes if args.upload else None,
                                      capture_output=True,timeout=args.max_time+5)
                try:
                    item=json.loads(result.stdout.decode('utf-8'))
                except ValueError:
                    item={'output':result.stdout.decode('utf-8',errors='replace')[:200]}
                item.update(exit_code=result.returncode,error=result.stderr.decode('utf-8',errors='replace').strip())
                actual=item.get('size_upload' if args.upload else 'size_download',0)
                item['success']=(result.returncode==0 and item.get('http_code')==200 and actual==args.bytes)
                return item
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as pool:
                streams=list(pool.map(run,commands))
            elapsed=time.perf_counter()-started
            total=sum(item.get('size_upload' if args.upload else 'size_download',0) for item in streams)
            mbps=total*8/elapsed/1e6
            check={'sample':sample+1,'streams':streams,'actual_bytes':total,'wall_seconds':round(elapsed,3),
                   'mbps_including_startup':round(mbps,3),'MB_per_second':round(mbps/8,3),
                   'success':all(item['success'] for item in streams)}
            report['checks'].append(check)
            print(json.dumps(check),flush=True)
            time.sleep(1)
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    label=('flclash' if args.flclash else 'bound-mihomo')+('-upload' if args.upload else '-download')
    if args.parallel>1:
        label+='-parallel'+str(args.parallel)
    if args.label:
        label+='-'+args.label
    if args.via_tokyo:
        label+='-via-tokyo'
    if args.hysteria2:
        label+='-hysteria2'
    (FOLDER/('speed-'+label+'.json')).write_text(json.dumps(report,indent=2),encoding='utf-8')
print('REPORT',str(FOLDER/('speed-'+label+'.json')),flush=True)
