"""Verify public HTTPS and console authentication over the physical WLAN."""
from datetime import datetime, timedelta, timezone
import http.client
import json
import socket
import ssl
import subprocess
from pathlib import Path

FOLDER=Path(__file__).resolve().parent
HOST='198-200-49-158.sslip.io'
IP='198.200.49.158'
ORIGIN='https://'+HOST+':8443'
wifi=json.loads(subprocess.run(['powershell.exe','-NoProfile','-Command',
    'Get-NetIPAddress -InterfaceAlias WLAN -AddressFamily IPv4 | Where-Object AddressState -eq Preferred | Select-Object -First 1 IPAddress,InterfaceIndex | ConvertTo-Json -Compress'],
    capture_output=True,check=True).stdout.decode('utf-8-sig'))

class PhysicalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        stream=socket.socket()
        stream.settimeout(self.timeout)
        stream.setsockopt(socket.IPPROTO_IP,31,socket.htonl(wifi['InterfaceIndex']))
        stream.bind((wifi['IPAddress'],0))
        stream.connect((IP,self.port))
        try:
            self.sock=self._context.wrap_socket(stream,server_hostname=HOST)
        except Exception:
            stream.close()
            raise

cookie=None
def request(method,path,data=None,headers=None):
    connection=PhysicalHTTPS(HOST,8443,timeout=12,context=ssl.create_default_context())
    extra={'Origin':ORIGIN}
    if cookie: extra['Cookie']=cookie
    if headers: extra.update(headers)
    body=json.dumps(data).encode() if data is not None else None
    if body is not None: extra['Content-Type']='application/json'
    try:
        connection.request(method,'/node-console/'+path,body=body,headers=extra)
        response=connection.getresponse()
        payload=response.read()
        return response.status,dict(response.getheaders()),payload
    finally: connection.close()

def main():
    global cookie
    report={'checked_at':datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'),
            'origin':ORIGIN,'path':'Physical WLAN; normal TLS trust and hostname validation','checks':[]}
    try:
        status,headers,body=request('GET','')
        assert status==200 and b'login-screen' in body
        report['checks'].append('HTTPS page and trusted certificate')
        status,_,body=request('GET','api/state'); assert status==401
        status,_,body=request('GET','api/session'); assert status==200 and not json.loads(body)['authenticated']
        login=json.loads((FOLDER/'panel-login.private.json').read_text(encoding='utf-8'))
        status,headers,body=request('POST','api/login',{'username':login['username'],'password':login['password']})
        assert status==200
        cookie_header=headers['Set-Cookie']
        assert all(value in cookie_header for value in ['Secure','HttpOnly','SameSite=Strict','Path=/node-console/'])
        cookie=cookie_header.split(';',1)[0]
        csrf=json.loads(body)['csrf']
        report['checks'].append('Login and Secure/HttpOnly/SameSite session')
        status,_,body=request('GET','api/state'); state=json.loads(body)
        assert status==200 and state['server_ip']==IP and state['service_active'] and not state['demo']
        report['state']={'server_ip':state['server_ip'],'server_port':state['server_port'],'exit_count':len(state['exits']),'service_active':state['service_active']}
        status,_,_=request('POST','api/routing',{'domains':state['domains'],'mode':state['routing_mode']}); assert status==403
        status,_,_=request('POST','api/routing',{'domains':state['domains'],'mode':state['routing_mode']},headers={'Origin':'https://invalid.example','X-CSRF-Token':csrf}); assert status==403
        report['checks'].append('CSRF and request origin enforcement')
        for path in ['app.js','style.css','mark.svg','rules/domestic-dns.yaml']:
            status,_,body=request('GET',path); assert status==200 and body
        status,_,_=request('POST','api/logout',{},headers={'X-CSRF-Token':csrf}); assert status==200
        status,_,_=request('GET','api/state'); assert status==401
        report['checks'].append('Assets, rules and logout')
        report['success']=True
    except Exception as error:
        report['success']=False
        report['error']=str(error) or type(error).__name__
    (FOLDER/'panel-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))
    if not report.get('success'): raise SystemExit(1)

if __name__ == '__main__':
    main()
