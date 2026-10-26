"""Read-only adopted-host diagnostics; only --run connects, never load-tests."""
import argparse
import json
import shlex
from ssh_access import FOLDER, connect, execute


REMOTE = r'''
import hashlib, json, os, re, subprocess, time
from pathlib import Path
from urllib.request import build_opener, ProxyHandler, Request

def read(path):
    return json.loads(Path(path).read_text())
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
    return {'exit_code':result.returncode,'output':result.stdout.decode('utf-8','replace').strip()}
def service(name):
    text=command(['systemctl','show',name,'--property=ActiveState','--property=UnitFileState',
        '--property=MainPID','--property=ExecMainStartTimestampMonotonic'])['output']
    return dict(line.split('=',1) for line in text.splitlines() if '=' in line)
def cpu():
    return [int(v) for v in Path('/proc/stat').read_text().splitlines()[0].split()[1:9]]
def udp():
    rows=[line.split()[1:] for line in Path('/proc/net/snmp').read_text().splitlines() if line.startswith('Udp:')]
    return dict(zip(rows[0],map(int,rows[1])))
def interface_counters(interface):
    parent=Path('/sys/class/net')/interface/'statistics'
    return {key:int((parent/key).read_text()) for key in ('rx_bytes','tx_bytes','rx_packets','tx_packets',
        'rx_errors','tx_errors','rx_dropped','tx_dropped')}
def epochs(record):
    return {source:service(record[source]) for source in ('hy2','xray')}

owner=Path('/var/lib/vps-panel')
registry=read(owner/'users.private.json')
hy2_registry=read(owner/'hy2.private.json')
records=[{'id':'admin','port':443,'enabled':True,'state':str(owner/'state.private.json'),
    'config':'/usr/local/etc/xray/config.json','xray':'xray.service','hy2':'raksmart-hy2@443.service'}]
for item in registry['users']:
    records.append({'id':item['id'],'port':item['port'],'enabled':item['enabled'],
        'state':str(owner/'users'/item['id']/'state.private.json'),
        'config':'/usr/local/etc/xray-members/'+item['id']+'/config.json',
        'xray':'xray-panel@'+item['id']+'.service','hy2':'raksmart-hy2@'+str(item['port'])+'.service'})
def sanitize(text):
    for item in records:
        text=text.replace(item['id'],'account-port-'+str(item['port']))
    return re.sub(r'--comment\s+(?:"[^"]*"|\S+)','--comment [redacted]',text)
def native(record):
    result={}
    for source in ('hy2','xray'):
        try:
            if source=='hy2':
                secret=hy2_registry['accounts'][record['id']]['api_secret']
                def request(resource):
                    url='http://127.0.0.1:'+str(18600+record['port'])+'/'+resource
                    with build_opener(ProxyHandler({})).open(Request(url,headers={'Authorization':secret}),timeout=3) as response:
                        return json.loads(response.read().decode('utf-8'))
                data=request('traffic').get('user',{'tx':0,'rx':0})
                result[source]={'available':True,'up_bytes':data['tx'],'down_bytes':data['rx'],
                    'online_clients':request('online').get('user',0)}
            else:
                response=command(['/usr/local/bin/xray','api','statsquery','--server=127.0.0.1:'+str(15000+record['port']),
                    '-timeout','3','-pattern','user>>>'])
                raw=response['output'];data=json.loads(raw[raw.find('{'):raw.rfind('}')+1])
                result[source]={'available':True,'up_bytes':sum(int(item.get('value',0)) for item in data.get('stat',[])
                    if item.get('name','').endswith('>>>traffic>>>uplink')),
                    'down_bytes':sum(int(item.get('value',0)) for item in data.get('stat',[])
                    if item.get('name','').endswith('>>>traffic>>>downlink'))}
        except Exception as error:
            result[source]={'available':False,'error_type':type(error).__name__}
    return result

route=command(['ip','route','get','1.1.1.1'])['output']
found=re.search(r'\bdev\s+(\S+)',route)
interface=found.group(1) if found else 'eth0'
ledger=read(owner/'traffic.private.json')
month=time.strftime('%Y-%m',time.gmtime())
accounts=[]
for record in records:
    state=read(record['state']);xray=read(record['config'])
    runtime='/usr/local/etc/raksmart-hy2/accounts/'+str(record['port'])+'.yaml'
    hy2=read(runtime)
    limits=ledger['users'][record['id']]
    totals=limits.get('months',{}).get(month,{'up_bytes':0,'down_bytes':0})
    auto=next(rule for rule in xray['routing']['rules'] if rule.get('user')==['panel-auto@exits.invalid'] and rule.get('network')=='tcp')
    target=auto['outboundTag']
    outbound=next(item for item in xray['outbounds'] if item['tag']==target)
    route_info={'protocol':outbound['protocol'],'target':'server' if target=='direct' else 'static'}
    if outbound['protocol']=='socks':
        endpoint=outbound['settings']['servers'][0]
        route_info.update(address=endpoint['address'],port=endpoint['port'])
    accounts.append({'port':record['port'],'enabled':record['enabled'],
        'quota_bytes':limits['quota_bytes'],'rate_bps':limits['rate_bps'],
        'month_total_bytes':sum(totals.get(key,0) for key in ('up_bytes','down_bytes')),
        'quota_exhausted':bool(limits['quota_bytes'] and sum(totals.get(key,0) for key in ('up_bytes','down_bytes'))>=limits['quota_bytes']),
        'auto_route':route_info,'hy2_congestion':hy2.get('congestion'),
        'ignore_client_bandwidth':hy2.get('ignoreClientBandwidth'),'hy2_disable_business_udp':hy2.get('disableUDP'),
        'client_bbr_profiles':re.findall(r'^\s*bbr-profile:\s*(\S+)\s*$',state.get('profile',''),re.M),
        'hy2_runtime_sha256':sha(runtime),'xray_config_sha256':sha(record['config']),
        'state_config_hash_matches':state.get('managed_hash')==sha(record['config']),
        'services':epochs(record)})

checkpoint_comparisons=[]
for folder in sorted(Path('/root').glob('vps-hy2-bbr-20261010-*')):
    checkpoint=folder/'checkpoint.private.json'
    if not checkpoint.is_file() or checkpoint.is_symlink():continue
    try:
        saved=read(checkpoint);port=saved['port'];path='/usr/local/etc/raksmart-hy2/accounts/'+str(port)+'.yaml'
        expected=saved['expected_sha256'];actual=sha(path)
        differences=[]
        for protected,metadata in saved['identity']['files'].items():
            wanted=expected if protected==path else metadata['sha256']
            if not Path(protected).is_file() or sha(protected)!=wanted:
                kind='account-state' if protected.endswith('state.private.json') else 'protected-source-or-config'
                differences.append(kind)
        checkpoint_comparisons.append({'port':port,'runtime_matches_expected':actual==expected,
            'runtime_matches_original':actual==saved['original']['sha256'],
            'pending_trial':saved.get('pending_sha256') is not None,'protected_difference_types':differences})
    except Exception as error:
        checkpoint_comparisons.append({'error_type':type(error).__name__})

before_epochs={record['port']:epochs(record) for record in records}
before={record['port']:native(record) for record in records}
start_cpu,start_udp,start_interface=cpu(),udp(),interface_counters(interface)
started=time.monotonic()
time.sleep(8)
end_cpu,end_udp,end_interface=cpu(),udp(),interface_counters(interface)
elapsed=time.monotonic()-started
after={record['port']:native(record) for record in records}
after_epochs={record['port']:epochs(record) for record in records}
live=[]
for record in records:
    port=record['port']
    for source in ('hy2','xray'):
        old,new=before[port][source],after[port][source]
        row={'port':port,'protocol':source,'available':old['available'] and new['available'],
            'epoch_unchanged':before_epochs[port][source]==after_epochs[port][source]}
        if row['available'] and row['epoch_unchanged']:
            for key in ('up_bytes','down_bytes'):
                delta=new[key]-old[key]
                row[key+'_delta']=delta;row[key.replace('_bytes','_mbps')]=round(delta*8/elapsed/1000000,3)
            if 'online_clients' in new:row['online_clients']=new['online_clients']
        live.append(row)
delta=[b-a for a,b in zip(start_cpu,end_cpu)];total=sum(delta)
interface_delta={key:end_interface[key]-start_interface[key] for key in start_interface}
speed=Path('/sys/class/net')/interface/'speed'
try:link_speed=int(speed.read_text())
except Exception:link_speed=None
tc={kind:command(['tc','-s',kind,'show','dev',interface]) for kind in ('qdisc','class','filter')}
tc['ingress_filter']=command(['tc','-s','filter','show','dev',interface,'parent','ffff:'])
tc['police']=command(['tc','-s','actions','list','action','police'])
for value in tc.values():value['output']=sanitize(value['output'])
netfilter={table:command(['iptables','-w','-t',table,'-S']) for table in ('filter','mangle')}
for value in netfilter.values():value['output']=sanitize(value['output'])
sysctls={key:int(command(['sysctl','-n',key])['output']) for key in ('net.core.rmem_max','net.core.wmem_max')}
report={'success':True,'checked_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
    'read_only':True,'load_tests':0,'accounts':accounts,'checkpoint_comparisons':checkpoint_comparisons,
    'sample_seconds':round(elapsed,3),'native_transport_activity':live,'interface':interface,'link_speed_mbps':link_speed,
    'interface_counter_delta':interface_delta,'interface_rx_mbps':round(interface_delta['rx_bytes']*8/elapsed/1000000,3),
    'interface_tx_mbps':round(interface_delta['tx_bytes']*8/elapsed/1000000,3),
    'cpu_percent':{'busy':round(100*(total-delta[3]-delta[4])/total,2),'iowait':round(100*delta[4]/total,2),'steal':round(100*delta[7]/total,2)},
    'load_averages':list(os.getloadavg()),'udp_delta':{key:end_udp[key]-start_udp[key] for key in start_udp},
    'udp_socket_buffers':command(['ss','-u','-a','-n','-m','sport','=',':443','or','sport','=',':1443','or','sport','=',':2443'])['output'],
    'sysctls':sysctls,'tc':tc,'netfilter':netfilter,
    'source_sha256':{name:sha('/opt/vps-panel/'+name) for name in ('panel/hy2.py','panel/accelerated_client.py','panel/telemetry.py')},
    'scope':'Global interface/UDP/CPU counters include all services; native snapshots bracket an 8-second idle observation and are not a throughput capacity test.'}
print(json.dumps(report,sort_keys=True))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true',required=True)
    parser.add_argument('--report',default='fast-regression-server-current.json')
    args=parser.parse_args()
    path=FOLDER/args.report
    if path.exists():
        raise RuntimeError('Current diagnostics report already exists')
    client=connect()
    try:
        code,out,_=execute(client,'python3 -c '+shlex.quote(REMOTE),timeout=100)
        if code:
            raise RuntimeError('Read-only remote diagnostics did not complete')
        report=json.loads(out)
        with path.open('x',encoding='utf-8') as stream:
            stream.write(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'success':report['success'],'report':str(path),'accounts':len(report['accounts']),
            'cpu_percent':report['cpu_percent'],'interface_rx_mbps':report['interface_rx_mbps'],
            'interface_tx_mbps':report['interface_tx_mbps'],'native_transport_activity':report['native_transport_activity']}))
    finally:
        client.close()


if __name__=='__main__':
    main()
