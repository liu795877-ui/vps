"""Read-only, in-memory sanitized comparison of both current VPS deployments.

No transfer tests, service reloads, config writes or remote uploads. Private
configs are read into memory and only explicit safe fields reach the report.
"""
import concurrent.futures
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

import yaml

FOLDER = Path(__file__).resolve().parent

REMOTE_META = r'''
import glob, hashlib, json, os, re, subprocess
from pathlib import Path
def run(args):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        return p.stdout.decode('utf-8','replace').strip() if p.returncode==0 else None
    except Exception:return None
services=[]
rows=run(['systemctl','list-units','--type=service','--all','--plain','--no-legend']) or ''
for line in rows.splitlines():
    name=line.strip().split()[0]
    if name in ('xray.service','raksmart-hy2.service','vps-panel.service','caddy.service') or re.fullmatch(r'(raksmart-hy2@[0-9]+|xray-panel@[a-f0-9]+)\.service',name):services.append(name)
props=['MainPID','ExecMainStartTimestampMonotonic','ActiveState','SubState','User','LimitNOFILE','MemoryLimit','CPUQuotaPerSecUSec','TasksMax','CapabilityBoundingSet','AmbientCapabilities']
entries=[]
for service in sorted(set(services)):
    raw=run(['systemctl','show',service]+['--property='+x for x in props]) or ''
    item={'service':service}
    for line in raw.splitlines():
        if '=' in line:
            k,v=line.split('=',1)
            if k in props:item[k]=v
    pid=int(item.get('MainPID','0'))
    if pid:
        try:
            command=Path('/proc/'+str(pid)+'/cmdline').read_bytes().split(b'\0')
            item['binary']=os.path.realpath('/proc/'+str(pid)+'/exe')
            item['config_paths']=[x.decode('utf-8') for x in command if x.startswith(b'/') and x.endswith((b'.json',b'.yaml',b'.yml'))]
        except Exception:pass
    entries.append(item)
protected=set(['/var/lib/vps-panel/state.private.json','/var/lib/vps-panel/auth.private.json','/var/lib/vps-panel/users.private.json','/var/lib/vps-panel/hy2.private.json','/usr/local/etc/xray/config.json','/usr/local/etc/raksmart-hy2/server.yaml'])
protected.update(glob.glob('/var/lib/vps-panel/users/*/state.private.json'))
protected.update(glob.glob('/usr/local/etc/raksmart-hy2/accounts/*.yaml'))
for item in entries:protected.update(item.get('config_paths',[]))
hashes={}
for name in sorted(protected):
    p=Path(name)
    if p.is_file():hashes[name]=hashlib.sha256(p.read_bytes()).hexdigest()
limits={}
p=Path('/var/lib/vps-panel/traffic.private.json')
if p.is_file():
    data=json.loads(p.read_text())
    limits={k:{f:v.get(f,0) for f in ('quota_bytes','rate_bps')} for k,v in data.get('users',{}).items()}
system={'kernel':run(['uname','-r']),'uptime':run(['uptime']), 'cpu_count':os.cpu_count(), 'loadavg':Path('/proc/loadavg').read_text().strip(),
        'cpu_stat':next((x for x in Path('/proc/stat').read_text().splitlines() if x.startswith('cpu ')),None)}
keys=['net.core.rmem_max','net.core.wmem_max','net.core.rmem_default','net.core.wmem_default','net.core.netdev_max_backlog','net.ipv4.tcp_congestion_control','net.ipv4.tcp_available_congestion_control','net.core.default_qdisc','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.ipv4.udp_rmem_min','net.ipv4.udp_wmem_min','net.ipv4.ip_local_port_range','net.ipv4.tcp_mtu_probing','net.ipv4.tcp_fastopen']
system['sysctl']={k:run(['sysctl','-n',k]) for k in keys}
route=run(['ip','-j','route','show','default'])
try:routes=json.loads(route) if route else []
except Exception:routes=[]
if not routes:
    txt=run(['ip','route','show','default']) or ''
    match=re.search(r'\bdev\s+([a-zA-Z0-9_.:-]+)',txt)
    routes=[{'dev':match.group(1)}] if match else []
ifaces=sorted(set(r['dev'] for r in routes if 'dev' in r))
system['interfaces']={}
for interface in ifaces:
    item={}
    for kind in ('qdisc','class','filter'):
        item[kind]=run(['tc','-s',kind,'show','dev',interface])
    p=Path('/sys/class/net')/interface/'mtu'
    item['mtu']=p.read_text().strip() if p.exists() else None
    system['interfaces'][interface]=item
versions={}
for binary in sorted(set(x.get('binary') for x in entries if x.get('binary'))):
    if binary in ('/usr/local/bin/xray','/usr/local/bin/raksmart-hysteria2','/usr/local/bin/hysteria','/usr/local/bin/hysteria2'):
        versions[binary]=run([binary,'version'])
print(json.dumps({'services':entries,'protected_sha256':hashes,'account_limits':limits,'system':system,'versions':versions}))
'''


def load_access(host):
    file=FOLDER.parent/('raksmart-'+host)/'ssh_access.py'
    spec=importlib.util.spec_from_file_location('ssh_'+host.replace('.','_'),file)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not module.HOST_KEYS.is_file():raise RuntimeError('Known host prerequisite unavailable')
    return module


def private_read(sftp,path):
    with sftp.open(path,'rb') as stream:return stream.read()


def safe_endpoint(value):
    if not isinstance(value,str):return value
    if '@' in value or '://' in value:return '<omitted-endpoint>'
    if len(value)>255 or any(x in value for x in '\r\n'):return '<invalid-endpoint>'
    return value


def safe_resolver(value):
    if isinstance(value,str) and '://' in value:
        parsed=urlsplit(value)
        return {'scheme':parsed.scheme,'hostname':parsed.hostname,'port':parsed.port}
    return safe_endpoint(value)


def hy2_safe(config):
    result={key:config.get(key) for key in ('listen','ignoreClientBandwidth','disableUDP')}
    result['congestion']={k:config['congestion'][k] for k in ('type','bbrProfile','maxRx','maxTx') if k in config.get('congestion',{})}
    result['bandwidth']={k:config['bandwidth'][k] for k in ('up','down','maxRx','maxTx') if k in config.get('bandwidth',{})}
    result['obfuscation_type']=config.get('obfs',{}).get('type')
    result['ignoreClientBandwidth_effective']=config.get('ignoreClientBandwidth',False)
    result['auth_type']=config.get('auth',{}).get('type')
    result['tls']={'configured':bool(config.get('tls') or config.get('acme')),
                   'certificate_file':config.get('tls',{}).get('cert'),
                   'acme':bool(config.get('acme'))}
    for key in ('quic','resolver','sniff','speedTest','udpIdleTimeout'):
        section=config.get(key)
        if isinstance(section,dict):
            allow={'quic':['initStreamReceiveWindow','maxStreamReceiveWindow','initConnReceiveWindow','maxConnReceiveWindow','maxIdleTimeout','maxIncomingStreams','disablePathMTUDiscovery'],
                   'resolver':['type'], 'sniff':['enable','timeout','rewriteDomain','tcpPorts','udpPorts'], 'speedTest':['enable']}
            result[key]={k:section[k] for k in allow.get(key,[]) if k in section}
        elif section is not None:result[key]=section
    stats=config.get('trafficStats',{})
    result['traffic_stats']={'enabled':bool(stats),'listen':stats.get('listen')}
    result['outbounds']=[]
    for outbound in config.get('outbounds',[]):
        kind=outbound.get('type')
        item={'name':outbound.get('name'),'type':kind}
        section=outbound.get(kind,{})
        if isinstance(section,dict):
            item.update({k:safe_endpoint(section[k]) for k in ('addr','mode','bindIPv4','bindIPv6','bindDevice') if k in section})
            item['authentication_configured']=bool(section.get('username') or section.get('password'))
        result['outbounds'].append(item)
    return result


def stream_safe(stream):
    result={k:stream[k] for k in ('network','security') if k in stream}
    if stream.get('sockopt'):result['sockopt']={k:stream['sockopt'][k] for k in ('tcpFastOpen','tcpCongestion','tcpMaxSeg','tcpKeepAliveInterval','tcpKeepAliveIdle','tcpUserTimeout','tcpNoDelay','domainStrategy','mark','tproxy') if k in stream['sockopt']}
    reality=stream.get('realitySettings',{})
    if reality:result['reality']={k:reality[k] for k in ('dest','target','serverNames','xver','show') if k in reality}
    tls=stream.get('tlsSettings',{})
    if tls:result['tls']={k:tls[k] for k in ('serverName','allowInsecure','alpn','minVersion','maxVersion') if k in tls}
    for key in ('tcpSettings','xhttpSettings','httpSettings','grpcSettings','wsSettings'):
        section=stream.get(key,{})
        if section:result[key]={k:section[k] for k in ('mode','noGRPCHeader','idle_timeout','health_check_timeout','multiMode') if k in section}
    return result


def xray_safe(config):
    result={'inbounds':[],'outbounds':[],'routing':{},'dns':{},'stats_configured':'stats' in config,
            'policy':config.get('policy',{}),'api_services':config.get('api',{}).get('services',[])}
    for inbound in config.get('inbounds',[]):
        settings=inbound.get('settings',{})
        item={k:inbound.get(k) for k in ('tag','listen','port','protocol')}
        item['clients_count']=len(settings.get('clients',[]))
        item['client_flows']=sorted(set(x.get('flow','') for x in settings.get('clients',[])))
        item['authentication_type']=settings.get('auth')
        item['udp']=settings.get('udp')
        item['stream']=stream_safe(inbound.get('streamSettings',{}))
        item['sniffing']={k:inbound['sniffing'][k] for k in ('enabled','destOverride','routeOnly','metadataOnly') if k in inbound.get('sniffing',{})}
        result['inbounds'].append(item)
    for outbound in config.get('outbounds',[]):
        item={k:outbound.get(k) for k in ('tag','protocol')}
        settings=outbound.get('settings',{})
        item['domain_strategy']=settings.get('domainStrategy')
        item['servers']=[{'address':s.get('address'),'port':s.get('port'),'authentication_configured':bool(s.get('users'))} for s in settings.get('servers',[])]
        item['mux']={k:outbound['mux'][k] for k in ('enabled','concurrency','xudpConcurrency','xudpProxyUDP443') if k in outbound.get('mux',{})}
        item['stream']=stream_safe(outbound.get('streamSettings',{}))
        result['outbounds'].append(item)
    routing=config.get('routing',{})
    result['routing']={k:routing[k] for k in ('domainStrategy','domainMatcher') if k in routing}
    result['routing']['rules']=[]
    for rule in routing.get('rules',[]):
        item={k:rule[k] for k in ('type','inboundTag','outboundTag','network','ip','port') if k in rule}
        if 'user' in rule:item['user_match_count']=len(rule['user'])
        if 'domain' in rule:item['domain_match_count']=len(rule['domain'])
        result['routing']['rules'].append(item)
    dns=config.get('dns',{})
    result['dns']={k:dns[k] for k in ('queryStrategy','disableCache','disableFallback','disableFallbackIfMatch') if k in dns}
    result['dns']['servers']=[safe_resolver(x if isinstance(x,str) else x.get('address')) for x in dns.get('servers',[])]
    return result


def node_safe(node):
    allowed=('type','name','server','port','network','tls','sni','skip-cert-verify','up','down','bbr-profile','udp','flow','client-fingerprint','max-stream-receive-window','max-conn-receive-window','disable-mtu-discovery','fast-open','mptcp')
    result={k:node[k] for k in allowed if k in node}
    result['certificate_pin_configured']=bool(node.get('fingerprint'))
    result['reality_key_configured']=bool(node.get('reality-opts',{}).get('public-key'))
    result['mux']={k:node['smux'][k] for k in ('enabled','protocol','max-connections','min-streams','max-streams','padding','statistic') if k in node.get('smux',{})}
    return result


def profile_safe(profile):
    dns=profile.get('dns',{})
    groups=[]
    for group in profile.get('proxy-groups',[]):
        item={k:group[k] for k in ('name','type','proxies','interval','timeout','lazy','expected-status') if k in group}
        if group.get('url'):item['health_check_target']=safe_resolver(group['url'])
        groups.append(item)
    return {'nodes':[node_safe(n) for n in profile.get('proxies',[])],
            'groups':groups,
            'dns':{k:dns[k] for k in ('enable','enhanced-mode','respect-rules','nameserver','default-nameserver','direct-nameserver','proxy-server-nameserver','ipv6') if k in dns},
            'rules_count':len(profile.get('rules',[]))}


def collect(host):
    access=load_access(host)
    ssh=access.connect()
    sftp=None
    try:
        cmd='python3 -c '+shlex.quote(REMOTE_META)
        code,out,_=access.execute(ssh,cmd,timeout=100)
        if code:raise RuntimeError('Remote sanitized metadata unavailable')
        before=json.loads(out)
        sftp=ssh.open_sftp();sftp.get_channel().settimeout(25)
        result={'host':host,'before':before,'configs':{},'profiles':{},'schema':1}
        paths=set(p for entry in before['services'] for p in entry.get('config_paths',[]))
        paths.update(p for p in before['protected_sha256'] if p.endswith(('.yaml','.json')) and ('/xray/' in p or '/raksmart-hy2/' in p))
        for path in sorted(paths):
            raw=private_read(sftp,path)
            config=json.loads(raw) if path.endswith('.json') else yaml.safe_load(raw)
            if not isinstance(config,dict):continue
            if 'inbounds' in config:result['configs'][path]={'kind':'xray','sha256':hashlib.sha256(raw).hexdigest(),'safe':xray_safe(config)}
            elif 'listen' in config and 'auth' in config:result['configs'][path]={'kind':'hy2','sha256':hashlib.sha256(raw).hexdigest(),'safe':hy2_safe(config)}
        for path in before['protected_sha256']:
            if path.endswith('/state.private.json'):
                raw=private_read(sftp,path);state=json.loads(raw)
                label='admin' if path=='/var/lib/vps-panel/state.private.json' else 'member-'+path.split('/')[-2]
                if state.get('profile'):result['profiles'][label]=profile_safe(yaml.safe_load(state['profile']))
        code,out,_=access.execute(ssh,cmd,timeout=100)
        if code:raise RuntimeError('Final sanitized metadata unavailable')
        after=json.loads(out)
        result['after']=after
        result['protected_files_unchanged']=before['protected_sha256']==after['protected_sha256']
        result['all_account_limits_unchanged']=before['account_limits']==after['account_limits']
        epoch=lambda data:{x['service']:(x.get('MainPID'),x.get('ExecMainStartTimestampMonotonic')) for x in data['services']}
        result['service_epochs_unchanged']=epoch(before)==epoch(after)
        result['success']=all(result[k] for k in ('protected_files_unchanged','all_account_limits_unchanged','service_epochs_unchanged'))
        return result
    finally:
        if sftp:sftp.close()
        ssh.close()


def main():
    report=FOLDER/'server-config-comparison-158-vs-63-current.json'
    if report.exists():raise RuntimeError('Existing report preserved; use a new name')
    result={'started_at':datetime.now(timezone.utc).isoformat(),'read_only':True,'speed_tests':0,'server_mutations':0,'servers':{}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs={pool.submit(collect,host):host for host in ('198.200.49.158','198.200.49.63')}
        for job in concurrent.futures.as_completed(jobs):
            host=jobs[job]
            try:result['servers'][host]=job.result()
            except Exception as error:result['servers'][host]={'success':False,'error_type':type(error).__name__}
    result['success']=all(v.get('success') for v in result['servers'].values())
    result['finished_at']=datetime.now(timezone.utc).isoformat()
    report.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'success':result['success'],'report':report.name,'hosts':{h:{k:v.get(k) for k in ('success','error_type','protected_files_unchanged','service_epochs_unchanged','all_account_limits_unchanged')} for h,v in result['servers'].items()}},ensure_ascii=False))


if __name__=='__main__':main()
