"""Show only performance settings and node identity checks, never credentials."""
import json
from pathlib import Path
import yaml

folder = Path('C:/Users/LENOVO/AppData/Roaming/com.follow/clash')
config = yaml.safe_load((folder/'config.yaml').read_text(encoding='utf-8'))
allow = ('unified-delay','tcp-concurrent','mode','mixed-port','external-controller',
         'external-controller-pipe','external-controller-unix','interface-name','find-process-mode')
print('CORE_SETTINGS', json.dumps({key:config.get(key) for key in allow},ensure_ascii=True))
node = next((node for node in config.get('proxies',[]) if node.get('name')=='RAKsmart-US'),None)
if node:
    node_allow = ('name','type','server','port','network','tls','flow','servername','client-fingerprint','dialer-proxy','interface-name','smux')
    print('NODE_SETTINGS',json.dumps({key:node.get(key) for key in node_allow},ensure_ascii=True))
print('PROXY_GROUPS',json.dumps([{key:group.get(key) for key in ('name','type','url','interval','timeout')}
                                for group in config.get('proxy-groups',[])],ensure_ascii=True))
print('TUN_SETTINGS',json.dumps({key:config.get('tun',{}).get(key) for key in
                               ('enable','stack','auto-route','auto-detect-interface','strict-route','mtu')},ensure_ascii=True))
prefs=json.loads((folder/'shared_preferences.json').read_text(encoding='utf-8'))
def walk(data,path=''):
    if isinstance(data,dict):
        for key,value in data.items():
            walk(value,path+'.'+key)
    elif isinstance(data,list):
        for index,value in enumerate(data):
            walk(value,path+f'[{index}]')
    elif isinstance(data,str) and data[:1] in ('{','['):
        try:
            walk(json.loads(data),path)
        except (ValueError,RecursionError):
            pass
    elif any(word in path.lower() for word in ('testurl','test_url','delaytest','unifieddelay','tcpconcurrent','latency')):
        if not any(word in path.lower() for word in ('secret','token','password')):
            print('APP_SETTING',path,str(data))
walk(prefs)
