"""Isolated Mihomo URL tests; no change to active FlClash or global routing."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import socket
import statistics
import subprocess
import time
from urllib.parse import urlencode, quote
from urllib.request import Request, build_opener, ProxyHandler
import yaml

FOLDER=Path(__file__).resolve().parent
binary=Path('C:/Users/LENOVO/.cockpit_tools/proxy-engine/release-490ee635-5175-46ca-a8c5-5e8a327cda34/mihomo.exe')
folder=FOLDER/'latency-client'
folder.mkdir(exist_ok=True)
profile=yaml.safe_load((FOLDER/'raksmart-reality.private.yaml').read_text(encoding='utf-8'))
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]
control_port=port()
secret=secrets.token_urlsafe(24)
profile.update({'mixed-port':port(),'external-controller':f'127.0.0.1:{control_port}',
                'secret':secret,'mode':'global','interface-name':'WLAN',
                'unified-delay':True,'tcp-concurrent':True,
                'dns':{'enable':False},'tun':{'enable':False},'log-level':'warning'})
profile['rules']=['MATCH,PROXY']
config=folder/'mihomo-test.private.yaml'
config.write_text(yaml.safe_dump(profile,allow_unicode=True),encoding='utf-8')
opener=build_opener(ProxyHandler({}))
def api(path,method='GET',body=None):
    request=Request(f'http://127.0.0.1:{control_port}'+path, method=method,
                    data=json.dumps(body).encode() if body is not None else None,
                    headers={'Authorization':'Bearer '+secret,'Content-Type':'application/json'})
    with opener.open(request,timeout=12) as response:
        data=response.read()
        return json.loads(data) if data else None
report={'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
        'method':'Isolated official Mihomo URLTest, bound to physical WLAN', 'checks':[]}
process=None
try:
    with (folder/'test.log').open('wb') as log:
        process=subprocess.Popen([str(binary),'-d',str(folder),'-f',str(config)],
                                 stdout=log,stderr=log,stdin=subprocess.DEVNULL,
                                 creationflags=subprocess.CREATE_NO_WINDOW)
        for _ in range(40):
            if process.poll() is not None:
                raise RuntimeError('Temporary Mihomo exited; inspect private log')
            try:
                report['version']=api('/version')
                break
            except OSError:
                time.sleep(.15)
        else:
            raise RuntimeError('Temporary Mihomo controller not ready')
        for unified in (True,):
            for url in ('https://www.gstatic.com/generate_204','http://www.gstatic.com/generate_204'):
                results=[]
                for _ in range(3):
                    query=urlencode({'url':url,'timeout':8000})
                    try:
                        result=api('/proxies/'+quote('RAKsmart-US',safe='')+'/delay?'+query)
                    except Exception as error:
                        result={'error':str(error)}
                    results.append(result)
                    print(json.dumps({'unified_delay':unified,'url':url,'result':result}),flush=True)
                    time.sleep(.4)
                values=[item['delay'] for item in results if 'delay' in item]
                report['checks'].append({'unified_delay':unified,'url':url,'results':results,
                                         'median_ms':statistics.median(values) if values else None})
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    (FOLDER/'mihomo-latency-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report),flush=True)
