"""Bounded official mainland-mirror DIRECT access-path diagnosis.

--check-local is offline. --run creates one private, loopback-only Mihomo with
MATCH,DIRECT, TUN off, physical WLAN and domestic DNS. It HEADs two official
mirror URLs, then measures each sequentially for <=12s and <=16 MiB read payload.
Body data is discarded. An ignored HTTP Range is stopped at the byte limit.
Mirror names do not establish physical server location or sustained bandwidth.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time
from urllib.parse import urlsplit

import yaml
import benchmark_fast_regression as fast
import benchmark_hy2_latency as base
import verify_hy2_clients as helpers

ENDPOINTS=(
    'https://mirrors.aliyun.com/ubuntu/dists/noble/Contents-amd64.gz',
    'https://mirrors.tuna.tsinghua.edu.cn/ubuntu/dists/noble/Contents-amd64.gz',
)
SECONDARY_ENDPOINTS=(
    'https://mirrors.ustc.edu.cn/ubuntu/dists/noble/Contents-amd64.gz',
    'https://mirrors.cloud.tencent.com/ubuntu/dists/noble/Contents-amd64.gz',
)
BYTE_CAP=16777216
SECONDS=12


class DirectClient(base.BenchClient):
    def __init__(self,directory,clock_start):
        directory.mkdir()
        helpers.IsolatedClient.__init__(self,directory,[])
        self.clock_start=clock_start
        self.children,self.all_children=set(),set()
        self.children_lock=threading.Lock()
        self.config=helpers.configuration([],self.proxy_port,self.control_port,self.secret)
        self.config['proxy-groups']=[]
        self.config['rules']=['MATCH,DIRECT']
        self.dns_port=helpers.free_port()
        self.config['dns']={'enable':True,'listen':'127.0.0.1:'+str(self.dns_port),'ipv6':False,
            'nameserver':['223.5.5.5','119.29.29.29'],'default-nameserver':['223.5.5.5','119.29.29.29'],
            'direct-nameserver':['223.5.5.5','119.29.29.29'],
            'proxy-server-nameserver':['223.5.5.5','119.29.29.29'],'respect-rules':True}
        self.candidate.write_text(yaml.safe_dump(self.config,allow_unicode=True,sort_keys=False),encoding='utf-8')


def header_summary(path):
    result={'http_status':None,'content_length':None,'range_supported':None,'content_range':None}
    try:text=path.read_text(encoding='iso-8859-1')
    except OSError:return result
    for line in text.splitlines():
        match=re.match(r'^HTTP/\S+\s+(\d{3})',line)
        if match:result.update(http_status=int(match.group(1)),content_length=None,content_range=None)
        elif ':' in line:
            key,value=line.split(':',1);key=key.lower();value=value.strip()
            if key=='content-length' and value.isdigit():result['content_length']=int(value)
            elif key=='accept-ranges':result['range_supported']=value.lower()=='bytes'
            elif key=='content-range' and re.fullmatch(r'bytes\s+\d+-\d+/\d+|bytes\s+\*/\d+',value):
                result['content_range']=value
    return result


def args_for(client,url,head,headers):
    result=[helpers.CURL,'--proxy','socks5h://127.0.0.1:'+str(client.proxy_port),'--noproxy','',
        '--location','--max-redirs','2','--connect-timeout','5','--max-time',str(6 if head else SECONDS),
        '--ssl-no-revoke','--silent','--show-error','--dump-header',str(headers),
        '--write-out','%{stderr}'+fast.MARKER.decode('ascii')+fast.FORMAT]
    if head:result+=['--head','--output','NUL']
    else:result+=['--range','0-'+str(BYTE_CAP-1)]
    return result+[url]


def track(client,process):
    with client.children_lock:
        client.children.add(process);client.all_children.add(process)


def untrack(client,process):
    if process.poll() is not None:
        with client.children_lock:client.children.discard(process)


def head(client,url):
    headers=client.directory/('head-'+secrets.token_hex(4)+'.private.txt')
    process=subprocess.Popen(args_for(client,url,True,headers),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=base.live.NO_WINDOW)
    track(client,process)
    try:
        output,error=process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill();output,error=process.communicate(timeout=4)
    finally:untrack(client,process)
    metrics,raw=fast.parse_metrics(error)
    return {'hostname':urlsplit(url).hostname,'curl_exit_code':process.returncode,
        **header_summary(headers),'http_code':metrics.get('http_code'),
        'success':process.returncode==0 and metrics.get('http_code') in (200,206),
        'tls_certificate_verification':True,
        'error_category':'none' if process.returncode==0 else fast.error_category(raw)}


def physical_socket_audit(client,wifi):
    # Local addresses are used only to compare binding; output reports a bool
    # and public destination addresses, never local IP/MAC or command output.
    command=("Get-NetTCPConnection -OwningProcess "+str(client.process.pid)+
        " -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 443 -and $_.State -eq 'Established' } | "
        "Select-Object LocalAddress,RemoteAddress,RemotePort | ConvertTo-Json -Compress")
    result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',command],
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,creationflags=base.live.NO_WINDOW)
    try:rows=json.loads(result.stdout.decode('utf-8-sig'))
    except (ValueError,UnicodeError):rows=[]
    if isinstance(rows,dict):rows=[rows]
    if not isinstance(rows,list):rows=[]
    usable=[row for row in rows if isinstance(row,dict)]
    return {'socket_observations':len(usable),'physical_wlan_local_address_matches':bool(usable) and
            all(row.get('LocalAddress')==wifi['IPAddress'] for row in usable),
            'actual_remote_ips':sorted({row.get('RemoteAddress') for row in usable if row.get('RemoteAddress')}),
            'local_ip_or_mac_saved':False}


def read_payload(process):
    actual,cap_reached=0,False
    while actual<BYTE_CAP:
        chunk=process.stdout.read(min(65536,BYTE_CAP-actual))
        if not chunk:break
        actual+=len(chunk)
    if actual==BYTE_CAP:
        cap_reached=True
        if process.poll() is None:process.kill()
    _,error=process.communicate(timeout=4)
    return actual,cap_reached,error


def download(client,url,wifi):
    headers=client.directory/('download-'+secrets.token_hex(4)+'.private.txt')
    started=time.monotonic()
    process=subprocess.Popen(args_for(client,url,False,headers),stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=base.live.NO_WINDOW)
    track(client,process)
    chains=[];targets=[];socket_audit=None
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            reader=pool.submit(read_payload,process)
            audit=None
            while not reader.done():
                state=client.api('/connections')
                for connection in (state.get('connections') or []):
                    metadata=connection.get('metadata') or {}
                    if metadata.get('host')==urlsplit(url).hostname:
                        chain=connection.get('chains') or []
                        if chain not in chains:chains.append(chain)
                        destination=metadata.get('destinationIP')
                        if destination and destination not in targets:targets.append(destination)
                        if audit is None:audit=pool.submit(physical_socket_audit,client,wifi)
                time.sleep(.05)
            actual,cap_reached,error=reader.result()
            payload_elapsed=time.monotonic()-started
            if audit is not None:socket_audit=audit.result()
        metrics,raw=fast.parse_metrics(error)
        public_headers=header_summary(headers)
        http=public_headers['http_status']
        chain_ok=any(chain==['DIRECT'] for chain in chains)
        measured={'hostname':urlsplit(url).hostname,'actual_download_bytes':actual,
            'maximum_payload_bytes':BYTE_CAP,'maximum_seconds':SECONDS,'elapsed_seconds':round(payload_elapsed,4),
            'observed_download_mbps_including_startup':round(actual*8/payload_elapsed/1e6,3),
            'http_code':http,'curl_exit_code':process.returncode,'byte_cap_reader_stopped':cap_reached,
            'full_requested_payload_read':actual==BYTE_CAP,'bounded_partial':0<actual<BYTE_CAP,
            'range_request':'bytes=0-16777215','range_honored':http==206,
            'response_headers':public_headers,'observed_connection_chains':chains,
            'direct_business_chain_verified':chain_ok,'controller_destination_ips':targets,
            'physical_socket_audit':socket_audit or {'socket_observations':0,'physical_wlan_local_address_matches':False},
            'tls_certificate_verification':True,'payload_files_written':0,
            'ttfb_ms':round(metrics['time_starttransfer']*1000,3) if isinstance(metrics.get('time_starttransfer'),(int,float)) else None,
            'error_category':'byte-cap-stop' if cap_reached else 'none' if process.returncode==0 else fast.error_category(raw),
            'success':actual>0 and http in (200,206) and chain_ok,
            'measurement_scope':'Bounded reader payload and short request window; in-flight/kernel bytes may exceed reader cap. Not sustained bandwidth.'}
        return measured
    finally:
        if process.poll() is None:
            process.kill();process.communicate(timeout=4)
        untrack(client,process)


def run(args):
    report_path=helpers.FOLDER/args.report
    directory=base.TEMP_ROOT/secrets.token_hex(8)
    client=None
    report={'success':False,'started_at':base.utc(),'configuration_changes':0,'credential_reads':0,
            'system_route_or_dns_changes':0,'user_proxy_changes':0,'payload_files_written':0,'results':[],
            'cleanup_errors':[],'maximum_total_reader_payload_bytes':2*BYTE_CAP,
            'geographic_limit':'Official mainland mirror organizations; endpoint physical location is not verified.'}
    endpoints=ENDPOINTS if args.source_set=='primary' else SECONDARY_ENDPOINTS
    report['source_set']=args.source_set
    report['official_endpoint_hostnames']=[urlsplit(url).hostname for url in endpoints]
    started=time.monotonic();stage='local-gate'
    try:
        helpers.require(not base.TEMP_ROOT.is_symlink(),'Unsafe private parent')
        report['private_directory_acl']=base.make_private(directory)
        report['script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['core_sha256']=hashlib.sha256(helpers.BINARY.read_bytes()).hexdigest()
        client=DirectClient(directory/'direct',started)
        report['isolated_configuration']={'interface-name':'WLAN','tun':False,'allow-lan':False,
            'bind-address':'127.0.0.1','rules':['MATCH,DIRECT'],'proxy_node_count':0,
            'dns_nameservers':['223.5.5.5','119.29.29.29'],'local_dns_listener':'isolated loopback ephemeral port'}
        if args.check_local:
            client.syntax()
            helpers.require(client.config['rules']==['MATCH,DIRECT'] and not client.config['proxies']
                and not client.config['tun']['enable'],'Forced DIRECT offline contract failed')
            report.update(success=True,offline_check=True,network_requests=0)
            return report
        helpers.require(not report_path.exists(),'Existing report must be preserved; choose a distinct report')
        wifi=base.live.physical_wifi()
        report['physical_interface_index']=wifi['InterfaceIndex']
        client.start(time.monotonic()+35)
        for url in endpoints:
            stage='head-'+urlsplit(url).hostname
            base.emit('phase-start',stage)
            result={'head':head(client,url)}
            if result['head']['success']:
                stage='download-'+urlsplit(url).hostname
                base.emit('phase-start',stage,maximum_payload_bytes=BYTE_CAP,maximum_seconds=SECONDS)
                result['download']=download(client,url,wifi)
                base.emit('phase-end',stage,bytes=result['download']['actual_download_bytes'],
                    mbps=result['download']['observed_download_mbps_including_startup'],
                    direct_chain=result['download']['direct_business_chain_verified'])
            else:result['download_skipped']='HEAD did not return successful HTTPS response'
            report['results'].append(result)
        measured=[item['download'] for item in report['results'] if 'download' in item]
        report['success']=bool(measured) and all(item['success'] for item in measured)
        report['all_endpoints_measured']=len(measured)==len(endpoints)
        return report
    except Exception as error:
        report.update(failure_stage=stage,error_type=type(error).__name__)
        return report
    finally:
        if client is not None:
            try:client.close()
            except BaseException as error:report['cleanup_errors'].append(type(error).__name__)
        try:
            helpers.require(directory.resolve().parent==base.TEMP_ROOT.resolve() and not directory.is_symlink()
                            and re.fullmatch(r'[a-f0-9]{16}',directory.name),'Unsafe private cleanup')
            if directory.exists():shutil.rmtree(str(directory))
        except BaseException as error:report['cleanup_errors'].append(type(error).__name__)
        report['temporary_private_files_removed']=not directory.exists()
        report['own_client_terminated']=client is None or client.process is None or client.process.poll() is not None
        report['own_curl_processes_terminated']=client is None or all(p.poll() is not None for p in client.all_children)
        if report['cleanup_errors'] or not all(report[key] for key in ('temporary_private_files_removed',
                'own_client_terminated','own_curl_processes_terminated')):report['success']=False
        report['finished_at']=base.utc()
        if args.run and not report_path.exists():report_path.write_text(json.dumps(report,indent=2),encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--run',action='store_true')
    group.add_argument('--check-local',action='store_true')
    parser.add_argument('--source-set',choices=('primary','secondary'),default='primary')
    parser.add_argument('--report',default='domestic-direct-current.json',type=lambda value:value
                        if re.fullmatch(r'[a-z0-9][a-z0-9-]{0,80}\.json',value) else parser.error('Safe JSON basename required'))
    result=run(parser.parse_args())
    print(json.dumps(result),flush=True)
    raise SystemExit(0 if result.get('success') else 1)
